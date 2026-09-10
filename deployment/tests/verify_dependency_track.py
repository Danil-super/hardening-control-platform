#!/usr/bin/env python3
"""Bounded live ingestion acceptance against a new, disposable DTrack 4.14.3 stack.

Uses the production syncDependencyTrack TypeScript adapter and actual HTTP/API
key authentication. The CycloneDX input is a labelled test fixture. Containers
have no external network, so this is NOT a CVE accuracy or feed freshness test.

Requirements: Docker/Compose v2.20+, Node 24 and `cd web && npm ci`.
No existing DTrack instance or HCP state is used. The new stack is removed when
the script exits; only the redacted protocol and service logs are retained.

Auth/team/event endpoints were checked against DependencyTrack/dependency-track
tag 4.14.3: resources/v1/{User,Team,Permission,Event,Project,Component}Resource.java.
"""

import argparse
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
NODE_ADAPTER = r"""
import { readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { compileServerModules } from './tests/_typescript-loader.mjs';
const input = JSON.parse(readFileSync(0, 'utf8'));
const names = new Set();
function visit(name) {
  if (names.has(name)) return;
  names.add(name);
  const source = readFileSync(path.join('lib', name + '.ts'), 'utf8');
  for (const match of source.matchAll(/from\s+["']@\/lib\/([^"']+)["']/g)) visit(match[1]);
}
visit('dependency-track');
const compiled = compileServerModules([...names]);
try {
  const { syncDependencyTrack } = await import(compiled.url('dependency-track'));
  const result = await syncDependencyTrack(input);
  if (!result.configured || !result.reportId) throw new Error('Adapter did not produce an upload report');
  const report = JSON.parse(readFileSync(path.join(process.env.HCP_REPORTS_DIR, result.reportId + '.json'), 'utf8'));
  console.log(JSON.stringify({ reportId: result.reportId, report }));
} finally {
  rmSync(compiled.directory, { recursive: true, force: true });
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18081, help="Unused loopback port for the disposable API")
    parser.add_argument("--output", default=".lab/dependency-track-acceptance", help="Directory for redacted evidence")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
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
    project = "hcp-dtrack-acceptance-" + run_id
    admin_password = secrets.token_urlsafe(36)
    database_password = secrets.token_urlsafe(36)
    sensitive = [admin_password, database_password]
    deadline = time.monotonic() + 660
    protocol = {
        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": "Live HCP adapter authentication and CycloneDX ingestion only",
        "fixture": True,
        "vulnerabilityFeedsChecked": False,
        "externalNetwork": "disabled for the disposable API and database",
        "limitations": ["No CVE findings or vulnerability coverage are asserted", "No live Linux host was scanned by this check",
                        "The HCP UI and application HTTP routes are tested in the separate HCP lab workflow"],
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
            raise TimeoutError("Acceptance check exceeded its 11-minute budget")
        return min(maximum, left)

    def command(argv, timeout=60, **kwargs):
        result = subprocess.run(argv, cwd=REPO, capture_output=True, text=True,
                                timeout=remaining(timeout), **kwargs)
        if result.returncode:
            raise RuntimeError(redact(f"Command {argv[0]} failed: {result.stderr[-2000:]}"))
        return result.stdout

    compose = ["docker", "compose", "-f", str(compose_file)]
    base = f"http://127.0.0.1:{args.port}"
    # Prevent proxy variables in a developer's environment forwarding credentials.
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(endpoint, body=None, method="GET", bearer=None, form=False, expected=(200,)):
        headers = {"Accept": "application/json"}
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
                "ports": [f"127.0.0.1:{args.port}:8080"], "volumes": ["api-data:/data"],
            },
        },
        "networks": {"default": {"internal": True}},
        "volumes": {"database": {}, "api-data": {}},
    }
    compose_file.write_text(json.dumps(stack, indent=2) + "\n")
    compose_file.chmod(0o600)
    started = False
    try:
        started = True
        command(compose + ["up", "-d", "--wait", "--wait-timeout", "300"], timeout=420)
        # The pinned image has a /health HEALTHCHECK; also verify readiness over
        # the exact host port used by the adapter before changing credentials.
        readiness_deadline = time.monotonic() + remaining(30)
        while time.monotonic() < readiness_deadline:
            try:
                health = api("/health/ready")
                if isinstance(health, dict) and health.get("status") == "UP":
                    break
            except (urllib.error.URLError, RuntimeError, TimeoutError):
                pass
            time.sleep(2)
        else:
            raise AssertionError("API/PostgreSQL readiness is not UP on the published port")
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

        # Disable remote analyzers/mirrors in this new test instance. The Docker
        # internal network already prevents feed downloads before configuration.
        for group, name in [("vuln-source", "nvd.enabled"), ("vuln-source", "epss.enabled"),
                            ("scanner", "npmaudit.enabled"), ("scanner", "ossindex.enabled"),
                            ("telemetry", "submission.enabled")]:
            api("/api/v1/configProperty", {"groupName": group, "propertyName": name,
                "propertyValue": "false", "propertyType": "BOOLEAN"}, method="POST", bearer=bearer)
        record("Remote feed and analyzer work is excluded from ingestion acceptance")

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

        host_alias = "hcp-ingestion-fixture-" + run_id
        report_id = host_alias + "-vulnerabilities"
        sbom_file = host_alias + ".json"
        components = [{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
                      {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
               "version": 1, "components": components}
        (runtime / "sbom" / sbom_file).write_text(json.dumps(bom))
        (runtime / "reports" / (report_id + ".json")).write_text(json.dumps({
            "inventoryHost": host_alias, "hostname": host_alias, "mode": "vulnerabilities", "os": "acceptance-fixture",
            "vulnerabilityScan": {"sbomFile": sbom_file, "partial": True, "message": "Synthetic ingestion fixture; no CVE audit executed"},
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
        protocol["status"] = "passed"
    except Exception as error:
        protocol["status"] = "failed"
        protocol["error"] = redact(str(error))
        print("FAIL " + protocol["error"], file=sys.stderr, flush=True)
    finally:
        if started:
            try:
                logs = subprocess.run(compose + ["logs", "--no-color", "--tail=150"], cwd=REPO,
                                      capture_output=True, text=True, timeout=20)
                (output / "services.log").write_text(redact(logs.stdout + logs.stderr))
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
        protocol["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (output / "protocol.json").write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")
    return 0 if protocol["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
