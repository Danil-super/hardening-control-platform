#!/usr/bin/env python3
"""Live, bounded NVD source and version-matching acceptance for DTrack 4.14.3.

Creates a NEW disposable instance, mirrors ONE real NVD CVE using the native
NVD REST API mirror, uploads a labelled CycloneDX fixture through the production
HCP adapter, and checks vulnerable/fixed versions with DTrack's internal analyzer.
No vulnerability records or findings are injected. OSV and other analyzers are
disabled. This does NOT assert complete NVD mirroring, GHSA coverage, or Astra
package coverage. Requires Linux Docker, Node 24 and `cd web && npm ci`.

--inspect-url performs only read-only readiness/configuration inspection on an
existing instance, with HCP_DEPENDENCY_TRACK_API_KEY supplied in the environment.
It never changes that instance and never equates one CVE with full mirror health.
"""

import argparse
import hashlib
import datetime
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


REPO = Path(__file__).resolve().parents[2]
IMAGE = "dependencytrack/apiserver:4.14.3"
from verify_dependency_track import NODE_ADAPTER

CVE = "CVE-2021-44228"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TARGET = NVD_API + "?cveId=" + CVE
VENDOR_ADVISORY = "https://logging.apache.org/security.html#CVE-2021-44228"
SAFE_PROPERTIES = {
    ("vuln-source", "nvd.enabled"), ("vuln-source", "nvd.api.enabled"),
    ("vuln-source", "nvd.api.last.modified.epoch.seconds"),
    ("vuln-source", "nvd.api.download.feeds"),
    ("vuln-source", "github.advisories.enabled"),
    ("vuln-source", "github.advisories.last.modified.epoch.seconds"),
    ("vuln-source", "google.osv.enabled"), ("scanner", "internal.enabled"),
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward API credentials to a redirect destination.
        raise RuntimeError("HTTP redirects are not allowed by this acceptance client")


def source_configuration(rows):
    if not isinstance(rows, list):
        raise AssertionError("Configuration endpoint did not return a property list")
    properties = {}
    for row in rows:
        key = (row.get("groupName"), row.get("propertyName"))
        if key in SAFE_PROPERTIES:
            properties["/".join(key)] = row.get("propertyValue")
        if key == ("vuln-source", "nvd.api.url"):
            # The URL could contain a secret query value on an existing server;
            # report only exact equality to the public standard endpoint.
            properties["nvdApiIsUnfilteredOfficialEndpoint"] = (row.get("propertyValue") or "").rstrip("/") == NVD_API
    return properties


def inspect_existing(args):
    parsed = urllib.parse.urlsplit(args.inspect_url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Inspect URL must be an HTTP(S) API base without credentials, query or fragment")
    if parsed.scheme == "http" and not args.allow_http:
        raise ValueError("Use HTTPS, or --allow-http only for your trusted local test network")
    key = os.environ.get("HCP_DEPENDENCY_TRACK_API_KEY", "").strip()
    if not key:
        raise ValueError("Set HCP_DEPENDENCY_TRACK_API_KEY in the environment; do not pass it in command arguments")
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    base = args.inspect_url.rstrip("/")
    def get(endpoint):
        request = urllib.request.Request(base + endpoint, headers={"X-Api-Key": key, "Accept": "application/json"})
        try:
            with client.open(request, timeout=20) as response:
                return json.loads(response.read(2_000_001))
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Read-only inspection {endpoint}: HTTP {error.code}") from None
    health = get("/health/ready")
    properties = source_configuration(get("/api/v1/configProperty"))
    issues = []
    if health.get("status") != "UP":
        issues.append("Dependency-Track readiness is not UP")
    if not properties.get("nvdApiIsUnfilteredOfficialEndpoint"):
        issues.append("NVD endpoint is not the unfiltered official API; review intended mirror configuration")
    for prop in ("vuln-source/nvd.enabled", "vuln-source/nvd.api.enabled", "scanner/internal.enabled"):
        if properties.get(prop) != "true":
            issues.append(prop + " is not enabled")
    for source in ("nvd.api", "github.advisories"):
        timestamp = properties.get(f"vuln-source/{source}.last.modified.epoch.seconds")
        try:
            stamp = int(timestamp)
            age_hours = (time.time() - stamp) / 3600
            properties[source + ".lastObservedModificationUtc"] = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat()
            properties[source + ".ageHours"] = round(age_hours, 2)
            enabled = source == "nvd.api" or properties.get("vuln-source/github.advisories.enabled") == "true"
            if enabled and (age_hours > 48 or age_hours < -1):
                issues.append(source + " observed modification timestamp is stale or in the future")
        except (TypeError, ValueError, OverflowError, OSError):
            if source == "nvd.api" or properties.get("vuln-source/github.advisories.enabled") == "true":
                issues.append("No valid " + source + " observed modification timestamp")
    if properties.get("vuln-source/google.osv.enabled") not in (None, ""):
        issues.append("OSV ecosystems are enabled; this conflicts with the intended HCP configuration")
    evidence = {"status": "inspection-only", "mutations": False, "fullMirrorVerified": False,
        "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "readinessStatus": health.get("status"), "properties": properties, "issues": issues,
        "requiredFollowUp": [
            "Review NistApiMirrorTask logs: complete total count, no fetch/persistence errors, no task still running",
            "A recent modification cursor alone does not prove that the initial complete mirror succeeded",
            "Run the positive and corrected-version fixture against the completed mirror",
            "Validate GHSA separately if enabled; its token and synchronization are not tested here",
        ]}
    output = (REPO / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "existing-source-inspection.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return 2 if issues else 0



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=".lab/dependency-track-sources", help="Directory for redacted evidence")
    parser.add_argument("--inspect-url", help="Read-only source status inspection of an existing API server")
    parser.add_argument("--allow-http", action="store_true", help="Allow plain HTTP inspection on a trusted test network")
    args = parser.parse_args()
    if args.inspect_url:
        return inspect_existing(args)
    if not shutil.which("docker") or not shutil.which("node"):
        parser.error("Docker/Compose and Node 24 must be installed")
    if not (REPO / "web/node_modules/typescript").is_dir():
        parser.error("Run npm ci in web first")

    output = (REPO / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    compose_file = output / "compose.json"
    if compose_file.exists():
        parser.error("Output already contains a stack definition; clean up that disposable stack and choose a new output directory")
    runtime = output / "runtime"
    (runtime / "reports").mkdir(parents=True)
    (runtime / "sbom").mkdir()
    run_id = uuid.uuid4().hex[:12]
    project = "hcp-dtrack-sources-" + run_id
    admin_password = secrets.token_urlsafe(36)
    database_password = secrets.token_urlsafe(36)
    sensitive = [admin_password, database_password]
    deadline = time.monotonic() + 1080
    protocol = {
        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "One live NVD CVE mirrored and analyzed against vulnerable and corrected component versions",
        "fixture": True,
        "vulnerabilityFeedsChecked": ["NVD targeted native API mirror"],
        "fullMirrorVerified": False, "astraCoverageVerified": False,
        "externalNetwork": "API egress enabled only after source configuration; disabled again before component analysis",
        "limitations": ["Only CVE-2021-44228 is mirrored; no full NVD mirror freshness or completeness is asserted",
                        "GHSA and other sources are not checked; OSV is explicitly disabled",
                        "No live Linux host or Astra package coverage is checked",
                        "A corrected version is asserted only against the selected CVE, not all vulnerabilities"],
        "checks": [],
        "status": "running",
    }

    def redact(text):
        for value in sensitive:
            if value:
                text = text.replace(value, "[REDACTED]")
        return text

    def remaining(maximum):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("Acceptance check exceeded its 18-minute budget")
        return min(maximum, left)

    def command(argv, timeout=60, **kwargs):
        result = subprocess.run(argv, cwd=REPO, capture_output=True, text=True,
                                timeout=remaining(timeout), **kwargs)
        if result.returncode:
            raise RuntimeError(redact(f"Command {argv[0]} failed: {result.stderr[-2000:]}"))
        return result.stdout

    compose = ["docker", "compose", "-f", str(compose_file)]
    base = ""  # Resolved from this run's API container after Compose starts it.
    # Prevent proxy variables in a developer's environment forwarding credentials.
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def api(endpoint, body=None, method="GET", bearer=None, form=False, expected=(200,)):
        # UserResource 4.14.3 produces text/plain for the two form-auth routes;
        # advertising only JSON would be rejected with HTTP 406 by JAX-RS.
        headers = {"Accept": "text/plain" if form else "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        data = None
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        request = urllib.request.Request(base + endpoint, data=data, headers=headers, method=method)
        try:
            response = client.open(request, timeout=remaining(20))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read().decode("utf8")
            if response.status not in expected:
                # Never include login/API-key response bodies in errors or artifacts.
                raise RuntimeError(f"Dependency-Track {endpoint}: HTTP {response.status}")
        try:
            return json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return payload

    def record(name, **details):
        protocol["checks"].append({"name": name, "status": "passed", **details})
        print("PASS " + name, flush=True)

    def health_probe(endpoint):
        # This diagnostic deliberately cannot request authenticated API routes.
        # It preserves HTTP errors and unexpected bodies instead of hiding the
        # distinction between an unhealthy database and an unreachable port.
        if endpoint not in ("/health", "/health/ready"):
            raise ValueError("Only unauthenticated health endpoints can be diagnosed")
        observation = {"endpoint": endpoint, "transport": "private-container-bridge"}
        request = urllib.request.Request(base + endpoint, headers={"Accept": "application/json"})
        try:
            try:
                response = client.open(request, timeout=remaining(5))
            except urllib.error.HTTPError as error:
                response = error
            with response:
                payload = response.read(4097)
                observation.update(httpStatus=response.status, bodyTruncated=len(payload) > 4096)
                body = redact(payload[:4096].decode("utf8", errors="replace"))
                try:
                    observation["body"] = json.loads(body)
                except json.JSONDecodeError:
                    observation["body"] = redact(body)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            observation["error"] = redact(f"{type(error).__name__}: {error}")
        return observation

    def database_ready(observation):
        health = observation.get("body")
        return (observation.get("httpStatus") == 200 and isinstance(health, dict)
                and health.get("status") == "UP" and isinstance(health.get("checks"), list)
                and any(isinstance(check, dict) and check.get("name") == "database"
                        and check.get("status") == "UP" for check in health["checks"]))

    stack = {
        "name": project,
        "services": {
            "postgres": {
                "image": "postgres:16-alpine", "mem_limit": "512m",
                "environment": {"POSTGRES_DB": "dtrack", "POSTGRES_USER": "dtrack", "POSTGRES_PASSWORD": database_password},
                "volumes": ["database:/var/lib/postgresql/data"],
                "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U dtrack -d dtrack"], "interval": "5s", "timeout": "3s", "retries": 20},
            },
            "api": {
                "image": IMAGE, "mem_limit": "3g", "cpus": 2,
                "depends_on": {"postgres": {"condition": "service_healthy"}},
                "environment": {
                    "ALPINE_DATABASE_MODE": "external", "ALPINE_DATABASE_URL": "jdbc:postgresql://postgres:5432/dtrack",
                    "ALPINE_DATABASE_DRIVER": "org.postgresql.Driver", "ALPINE_DATABASE_USERNAME": "dtrack",
                    "ALPINE_DATABASE_PASSWORD": database_password, "ALPINE_WORKER_THREADS": "2",
                    "ALPINE_DATABASE_POOL_MAX_SIZE": "10", "ALPINE_DATABASE_POOL_MIN_IDLE": "2",
                    "EXTRA_JAVA_OPTIONS": "-Xms512m -Xmx2g -XX:ActiveProcessorCount=2",
                    "ALPINE_HTTP_TIMEOUT_CONNECTION": "3", "ALPINE_HTTP_TIMEOUT_SOCKET": "3",
                },
                "volumes": ["api-data:/data"],
            },
        },
        "networks": {"default": {"internal": True}},
        "volumes": {"database": {}, "api-data": {}},
    }
    compose_file.write_text(json.dumps(stack, indent=2) + "\n")
    compose_file.chmod(0o600)
    started = False
    egress_network = project + "-egress"
    egress_created = False
    try:
        started = True
        command(compose + ["up", "-d", "--wait", "--wait-timeout", "300"], timeout=420)
        # Docker does not publish loopback ports for the isolated network on
        # every engine version. Address only the API container created by this
        # Compose project, via the bridge shared with the Linux Docker host.
        # The API/database still have no route to external feeds.
        api_container = command(compose + ["ps", "-q", "api"]).strip()
        if len(api_container) != 64 or any(char not in "0123456789abcdef" for char in api_container):
            raise AssertionError("Compose did not identify exactly one API container")
        networks = json.loads(command(["docker", "inspect", api_container,
                                       "--format", "{{json .NetworkSettings.Networks}}"]))
        network_name = project + "_default"
        if not isinstance(networks, dict) or set(networks) != {network_name}:
            raise AssertionError("Disposable API must belong only to its own isolated Compose network")
        api_address = ipaddress.IPv4Address(networks[network_name]["IPAddress"])
        if (not api_address.is_private or api_address.is_loopback or api_address.is_link_local
                or api_address.is_multicast or api_address.is_reserved or api_address.is_unspecified):
            raise AssertionError("Disposable API must have a private, routable bridge address")
        base = f"http://{api_address}:8080"
        protocol["apiTransport"] = {"kind": "private-container-bridge", "network": network_name,
                                    "container": api_container, "endpoint": base, "publishedPorts": False}
        # The pinned image has a /health HEALTHCHECK; verify database readiness
        # again over the exact private address used by the production adapter.
        readiness_deadline = time.monotonic() + remaining(30)
        while time.monotonic() < readiness_deadline:
            observation = health_probe("/health/ready")
            protocol["readiness"] = observation
            if database_ready(observation):
                break
            time.sleep(2)
        else:
            protocol["aggregateHealth"] = health_probe("/health")
            raise AssertionError("API/PostgreSQL readiness is not UP on its private bridge address: "
                                 + json.dumps(observation, ensure_ascii=True))
        protocol["image"] = IMAGE
        protocol["imageDigests"] = json.loads(command([
            "docker", "image", "inspect", IMAGE, "--format", "{{json .RepoDigests}}",
        ]))
        record("Real Dependency-Track and PostgreSQL are ready")

        # Exact 4.14.3 API: forceChangePassword accepts old credentials and
        # returns an empty HTTP 200; a separate login returns the JWT string.
        api("/api/v1/user/forceChangePassword", {"username": "admin", "password": "admin",
            "newPassword": admin_password, "confirmPassword": admin_password}, method="POST", form=True)
        bearer = api("/api/v1/user/login", {"username": "admin", "password": admin_password}, method="POST", form=True)
        if not isinstance(bearer, str) or bearer.count(".") != 2:
            raise AssertionError("Admin login did not return a JWT")
        sensitive.append(bearer)
        record("Initial administrator password changed and authenticated")

        # Configure while the fresh API is still isolated. Defaults may start
        # tasks at boot; restarting below makes NistMirrorTask re-read flags.
        for group, name in [("vuln-source", "nvd.enabled"), ("vuln-source", "epss.enabled"),
                            ("vuln-source", "github.advisories.enabled"),
                            ("vuln-source", "google.osv.alias.sync.enabled"),
                            ("scanner", "npmaudit.enabled"), ("scanner", "ossindex.enabled"),
                            ("scanner", "snyk.enabled"), ("scanner", "vulndb.enabled"),
                            ("scanner", "trivy.enabled"), ("scanner", "internal.fuzzy.enabled"),
                            ("telemetry", "submission.enabled")]:
            api("/api/v1/configProperty", {"groupName": group, "propertyName": name,
                "propertyValue": "false", "propertyType": "BOOLEAN"}, method="POST", bearer=bearer)
        settings = [("vuln-source", "google.osv.enabled", "", "STRING"),
                    ("scanner", "internal.enabled", "true", "BOOLEAN"),
                    ("vuln-source", "nvd.api.url", NVD_TARGET, "URL"),
                    ("vuln-source", "nvd.api.enabled", "true", "BOOLEAN"),
                    ("vuln-source", "nvd.api.download.feeds", "false", "BOOLEAN"),
                    ("vuln-source", "nvd.enabled", "true", "BOOLEAN")]
        for group, name, value, kind in settings:
            api("/api/v1/configProperty", {"groupName": group, "propertyName": name,
                "propertyValue": value, "propertyType": kind}, method="POST", bearer=bearer)
        properties = source_configuration(api("/api/v1/configProperty", bearer=bearer))
        if properties.get("vuln-source/google.osv.enabled") not in (None, ""):
            raise AssertionError("OSV ecosystems were not disabled")
        protocol["sourceConfiguration"] = properties
        record("Only the native targeted NVD source and internal analyzer are enabled; OSV disabled")

        # Fetch the same public source independently for its response checksum,
        # actual publication/modification time, affected CPE data, and CVSS score.
        # These bytes are never injected into DTrack; its native mirror downloads
        # the advisory independently from NVD after restart.
        payload = None
        for attempt in range(6):
            try:
                request = urllib.request.Request(NVD_TARGET, headers={"Accept": "application/json", "User-Agent": "HCP-source-acceptance/1.0"})
                with client.open(request, timeout=remaining(30)) as response:
                    payload = response.read(2_000_001)
                    if len(payload) > 2_000_000:
                        raise ValueError("Targeted NVD response is unexpectedly large")
                break
            except (urllib.error.URLError, OSError, TimeoutError):
                if attempt == 5:
                    raise
                time.sleep(10)
        document = json.loads(payload)
        records = document.get("vulnerabilities", [])
        if document.get("totalResults") != 1 or len(records) != 1 or records[0].get("cve", {}).get("id") != CVE:
            raise AssertionError("NVD did not return exactly the requested real CVE")
        upstream = records[0]["cve"]
        if not upstream.get("configurations") or not upstream.get("metrics", {}).get("cvssMetricV31"):
            raise AssertionError("NVD advisory has no usable affected-version or CVSS 3.1 data")
        (output / "nvd-response.json").write_bytes(payload)
        protocol["upstream"] = {"url": NVD_TARGET, "sha256": hashlib.sha256(payload).hexdigest(),
            "retrievedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cve": CVE, "published": upstream["published"], "lastModified": upstream["lastModified"],
            "vendorAdvisory": VENDOR_ADVISORY, "scope": "one current real advisory, not a complete database"}
        record("Live NVD response contains the selected CVE, affected versions and CVSS", **protocol["upstream"])

        command(["docker", "network", "create", egress_network])
        egress_created = True
        command(["docker", "network", "connect", egress_network, api_container])
        command(compose + ["restart", "api"], timeout=100)
        mirror_deadline = time.monotonic() + remaining(360)
        mirrored = None
        while time.monotonic() < mirror_deadline:
            try:
                if not database_ready(health_probe("/health/ready")):
                    time.sleep(3)
                    continue
                candidate = api("/api/v1/vulnerability/source/NVD/vuln/" + CVE,
                                bearer=bearer, expected=(200, 404))
                properties = source_configuration(api("/api/v1/configProperty", bearer=bearer))
                cursor = properties.get("vuln-source/nvd.api.last.modified.epoch.seconds")
                if (isinstance(candidate, dict) and candidate.get("vulnId") == CVE
                        and candidate.get("source") == "NVD" and candidate.get("affectedComponents")
                        and cursor and int(cursor) > 0):
                    mirrored = candidate
                    break
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(3)
        if mirrored is None:
            raise TimeoutError("Native targeted NVD mirror did not persist the CVE, affected versions and completion cursor")
        upstream_score = next(item["cvssData"]["baseScore"] for item in upstream["metrics"]["cvssMetricV31"] if item["type"] == "Primary")
        if float(mirrored.get("cvssV3BaseScore", -1)) != float(upstream_score):
            raise AssertionError("Mirrored CVSS 3.1 score differs from the live NVD Primary metric")
        expected_cursor = int(datetime.datetime.fromisoformat(upstream["lastModified"]).replace(tzinfo=datetime.timezone.utc).timestamp())
        if int(cursor) != expected_cursor:
            raise AssertionError("NVD modification changed during the check or mirror cursor differs; rerun against a consistent advisory")
        (output / "mirrored-cve.json").write_text(json.dumps(mirrored, indent=2) + "\n")
        record("Native NVD mirror persisted affected versions, exact CVSS and modification cursor",
               cve=CVE, cvssV3=upstream_score, cursor=cursor, fullMirrorVerified=False)
        command(["docker", "network", "disconnect", egress_network, api_container])
        record("API external network disconnected before internal vulnerability analysis")

        team = api("/api/v1/team", {"name": "hcp-upload-only-" + run_id}, method="PUT", bearer=bearer, expected=(201,))
        team_id = str(uuid.UUID(team["uuid"]))
        for permission in ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"]:
            api(f"/api/v1/permission/{permission}/team/{team_id}", body={}, method="POST", bearer=bearer)
        created_key = api(f"/api/v1/team/{team_id}/key", method="PUT", bearer=bearer, expected=(201,))
        api_key = created_key.get("key")
        if not isinstance(api_key, str) or len(api_key) < 20:
            raise AssertionError("Team API did not return a one-time key")
        sensitive.append(api_key)
        record("Dedicated HCP API key has only BOM upload and project creation permissions")

        host_alias = "hcp-nvd-fixture-" + run_id
        report_id = host_alias + "-vulnerabilities"
        sbom_file = host_alias + ".json"
        components = [{"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core",
                       "version": version, "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@" + version,
                       "cpe": "cpe:2.3:a:apache:log4j:" + version + ":*:*:*:*:*:*:*",
                       "bom-ref": "log4j-core-" + version} for version in ("2.14.1", "2.17.1")]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
               "version": 1, "components": components}
        (runtime / "sbom" / sbom_file).write_text(json.dumps(bom))
        (runtime / "reports" / (report_id + ".json")).write_text(json.dumps({
            "inventoryHost": host_alias, "hostname": host_alias, "mode": "vulnerabilities", "os": "acceptance-fixture",
            "vulnerabilityScan": {"sbomFile": sbom_file, "partial": True, "message": "Labelled fixture for one real NVD CVE; no Linux host audited"},
        }))
        adapter_env = os.environ | {"HCP_STATE_DIR": str(runtime), "HCP_REPORTS_DIR": str(runtime / "reports"),
            "HCP_DEPENDENCY_TRACK_URL": base, "HCP_DEPENDENCY_TRACK_API_KEY": api_key}
        result = subprocess.run(["node", "--input-type=module", "-e", NODE_ADAPTER], cwd=REPO / "web",
            input=json.dumps({"hostAlias": host_alias, "vulnerabilityReportId": report_id}),
            env=adapter_env, capture_output=True, text=True, timeout=remaining(75))
        if result.returncode:
            raise RuntimeError("Production HCP adapter failed: " + redact(result.stderr[-2500:]))
        adapted = json.loads(result.stdout)
        hcp_report = adapted["report"]
        token = str(uuid.UUID(hcp_report["scanner"]["processingToken"]))
        if hcp_report["scanner"].get("analysisStatus") != "pending" or hcp_report["scanner"].get("partial") is not True:
            raise AssertionError("HCP mistakenly claims completed analysis on upload acceptance")
        if not hcp_report.get("findings") or any(item["status"] != "manual" for item in hcp_report["findings"]):
            raise AssertionError("HCP upload report must require manual analysis review")
        (output / "hcp-report.json").write_text(json.dumps(hcp_report, ensure_ascii=False, indent=2) + "\n")
        record("Production HCP adapter authenticated and uploaded CycloneDX", reportId=adapted["reportId"],
               processingToken=token, hcpAnalysisStatus="pending", hcpFindingStatus="manual")

        processing_deadline = time.monotonic() + remaining(180)
        query = urllib.parse.urlencode({"name": host_alias, "version": "acceptance-fixture"})
        while time.monotonic() < processing_deadline:
            event = api("/api/v1/event/token/" + token, bearer=bearer)
            if event.get("processing") is False:
                dt_project = api("/api/v1/project/lookup?" + query, bearer=bearer)
                observed = api("/api/v1/component/project/" + dt_project["uuid"], bearer=bearer)
                expected_packages = {(item["name"], item["version"], item["purl"]) for item in components}
                observed_packages = {(item.get("name"), item.get("version"), item.get("purl")) for item in observed}
                if observed_packages == expected_packages:
                    record("BOM processing finished and both components are stored", processing=False,
                           projectUuid=dt_project["uuid"], componentCount=len(observed), components=components)
                    break
            time.sleep(2)
        else:
            raise TimeoutError("BOM processing and component persistence did not complete within 180 seconds")
        if len(observed) != 2 or {item.get("cpe") for item in observed} != {item["cpe"] for item in components}:
            raise AssertionError("DTrack did not preserve both fixture components and their exact CPE identifiers")
        analysis = api("/api/v1/finding/project/" + dt_project["uuid"] + "/analyze",
                       method="POST", bearer=bearer)
        analysis_token = str(uuid.UUID(analysis["token"]))
        analysis_deadline = time.monotonic() + remaining(180)
        while time.monotonic() < analysis_deadline:
            if api("/api/v1/event/token/" + analysis_token, bearer=bearer).get("processing") is False:
                break
            time.sleep(3)
        else:
            raise TimeoutError("Real on-demand analysis did not complete")
        findings = api("/api/v1/finding/project/" + dt_project["uuid"] + "?suppressed=true", bearer=bearer)
        if not isinstance(findings, list):
            raise AssertionError("DTrack findings endpoint did not return a list")
        matches = [item for item in findings if item.get("vulnerability", {}).get("vulnId") == CVE
                   and item.get("vulnerability", {}).get("source") == "NVD"]
        found_versions = {item.get("component", {}).get("version") for item in matches}
        if len(matches) != 1 or found_versions != {"2.14.1"}:
            raise AssertionError("Expected NVD CVE on 2.14.1 only after completed analysis; observed " + repr(found_versions))
        (output / "findings.json").write_text(json.dumps(findings, indent=2) + "\n")
        record("Real internal analyzer identifies vulnerable version and excludes corrected version for the selected CVE",
               cve=CVE, vulnerableVersion="2.14.1", correctedVersion="2.17.1", analysisToken=analysis_token,
               findingCount=len(matches), fullDatabaseCoverage=False)
        protocol["status"] = "passed"
    except Exception as error:
        protocol["status"] = "failed"
        protocol["error"] = redact(str(error))
        print("FAIL " + protocol["error"], file=sys.stderr, flush=True)
    finally:
        if started:
            if protocol["status"] == "failed":
                # Compare the exact readiness endpoint inside the container to
                # diagnose Docker bridge connectivity independently of database
                # health. No environment, credentials or authenticated API
                # response is included in this bounded diagnostic.
                try:
                    internal = subprocess.run(compose + ["exec", "-T", "api", "curl", "--silent", "--show-error",
                        "--max-time", "5", "--noproxy", "*", "--write-out", "\nHTTP_STATUS=%{http_code}\n",
                        "http://127.0.0.1:8080/health/ready"], cwd=REPO,
                        capture_output=True, text=True, timeout=10)
                    diagnostic = {"transport": "container-loopback", "endpoint": "/health/ready",
                                  "exitCode": internal.returncode, "output": redact(internal.stdout[:4096]),
                                  "error": redact(internal.stderr[:1024])}
                    protocol["containerReadiness"] = diagnostic
                    print("HEALTH " + json.dumps(diagnostic, ensure_ascii=True), file=sys.stderr, flush=True)
                except Exception as error:
                    protocol["healthDiagnosticError"] = redact(str(error))
            try:
                logs = subprocess.run(compose + ["logs", "--no-color", "--tail=150"], cwd=REPO,
                                      capture_output=True, text=True, timeout=20)
                safe_logs = redact(logs.stdout + logs.stderr)
                (output / "services.log").write_text(safe_logs)
                if protocol["status"] == "failed":
                    print("Service log tail (redacted, at most 12000 characters):\n" + safe_logs[-12000:],
                          file=sys.stderr, flush=True)
            except Exception as error:
                protocol["logCollectionError"] = redact(str(error))
            try:
                stopped = subprocess.run(compose + ["down", "-v", "--remove-orphans"], cwd=REPO,
                                         capture_output=True, text=True, timeout=45)
                if stopped.returncode:
                    raise RuntimeError("Disposable stack cleanup failed; use compose.json to remove it")
            except Exception as error:
                protocol["status"] = "failed"
                protocol["cleanupError"] = redact(str(error))
        if egress_created:
            try:
                removed = subprocess.run(["docker", "network", "rm", egress_network], cwd=REPO,
                                         capture_output=True, text=True, timeout=15)
                if removed.returncode:
                    raise RuntimeError("Disposable egress network cleanup failed")
            except Exception as error:
                protocol["status"] = "failed"
                protocol["egressCleanupError"] = redact(str(error))
        protocol["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (output / "protocol.json").write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")
    return 0 if protocol["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
