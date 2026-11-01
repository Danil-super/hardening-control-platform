#!/usr/bin/env python3
"""Acceptance checks against the running, disposable HCP Docker laboratory."""
import argparse
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def verify_scheduled_response(completed, host):
    """A real scheduler CLI must fail on an incomplete or rejected API run."""
    payload = json.loads(completed.stdout)
    results = payload.get("results")
    if (not isinstance(results, list) or len(results) != 1
            or results[0].get("hostAlias") != host
            or not isinstance(payload.get("reportRunId"), str)
            or not payload["reportRunId"].startswith("schedule-")):
        raise AssertionError("Scheduled API lost its requested host or run correlation")
    result = results[0]
    partial = bool(result.get("partial") or result.get("error"))
    if (not isinstance(result.get("partial"), bool)
            or payload.get("partial") is not partial
            or payload.get("ok") is not (not partial)
            or (completed.returncode == 0) is not (not partial)):
        raise AssertionError("Scheduled CLI success does not match the API's incomplete/error evidence")
    return payload, result


def verify_scheduled_binding(item, host, observed_binding):
    """The saved scheduler report must retain the authenticated target identity."""
    raw = item["raw"]
    binding = item.get("assetBinding")
    identity_keys = ("assetId", "alias", "generation", "machineIdSha256",
                     "sshHostKeyFingerprint", "connectionId")
    if (not isinstance(binding, dict) or binding.get("status") != "verified"
            or raw.get("assetBinding") != binding or binding.get("alias") != host
            or item.get("assetBindingInvalid") is not False
            or raw.get("inventoryHost") != host or item.get("inventoryHost") != host
            or item.get("reportTimeValid") is not True
            or any(binding.get(key) is None or binding.get(key) != observed_binding.get(key)
                   for key in identity_keys)):
        raise AssertionError("Scheduled report lost its verified SSH/machine identity or changed the target")


def verify_native_package_snapshot(item, native_output):
    """Compare the scheduled inventory with an independent native dpkg query."""
    raw = item["raw"]
    inventory = raw.get("packageInventory", {})
    packages = raw.get("packages", [])
    native = []
    for line in native_output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise AssertionError("Independent dpkg query returned an incomplete record")
        if fields[0] == "installed":
            native.append(tuple(fields[1:]))
    collected = [(p.get("name"), p.get("version"), p.get("arch")) for p in packages]
    if (not native or sorted(native) != sorted(collected)
            or any(p.get("manager") != "dpkg" for p in packages)
            or inventory.get("manager") != "dpkg"
            or inventory.get("packageCount") != len(native)
            or inventory.get("error") or inventory.get("partial") is not False
            or item.get("partial") is not False):
        raise AssertionError("Scheduled inventory differs from the real installed package database")


def verify_known_ssh_deviations(item):
    failed = [finding for finding in item["findings"] if finding.get("status") == "failed"]
    for evidence in ("PermitRootLogin=yes", "MaxAuthTries=8"):
        if not any(evidence in finding.get("evidence", "") for finding in failed):
            observed = [{"id": f.get("id"), "status": f.get("status"), "evidence": f.get("evidence")}
                        for f in item["findings"] if f.get("category") == "SSH"]
            raise AssertionError(f"Known lab deviation was not detected: {evidence}; observed={observed}")


def verify_unavailable_cve_report(payload, item, packages, freshness):
    """An unavailable DB is saved evidence of no scan, never a clean verdict."""
    raw = item["raw"]
    scan = raw["vulnerabilityScan"]
    coverage = scan["coverage"]
    scanner = raw["scanner"]
    count = len(packages["raw"]["packages"])
    if (payload.get("ok") is not True or payload.get("partial") is not True
            or item.get("partial") is not True or scanner.get("partial") is not True
            or scanner.get("available") is not False or scan.get("partial") is not True):
        raise AssertionError("Unavailable CVE source must remain a saved partial/unavailable report")
    if (freshness not in {"missing", "stale", "unknown"}
            or scan.get("providerMode") != "offline"
            or scan.get("databaseFreshness", {}).get("status") != freshness):
        raise AssertionError("Unavailable CVE report lost its offline database state")
    if (scan.get("checkedPackages") != 0 or coverage.get("scannedPackages") != 0
            or coverage.get("inventoryPackages") != count or count <= 0
            or coverage.get("complete") is not False or not coverage.get("reasons")):
        raise AssertionError("Unavailable CVE source claims checked packages or complete coverage")
    if (item["score"] is not None or raw["summary"]["score"] is not None
            or scan.get("vendorAssessment", {}).get("verified") is not False
            or scan.get("sourceEvidence") is not None):
        raise AssertionError("Unavailable CVE source claims a score, verified vendor or scan evidence")
    if (payload.get("reportId") != item.get("id")
            or scan.get("sourcePackageReportId") != packages["id"]):
        raise AssertionError("Unavailable CVE report is not bound to the saved package inventory")
    for findings in (raw["findings"], item["findings"]):
        if (not findings or any(finding.get("status") == "passed"
                               or finding.get("id") == "trivy_no_known_vulnerabilities"
                               for finding in findings)
                or not any(finding.get("id") == "trivy_scan_unavailable"
                           and finding.get("status") == "manual"
                           and "failure=database" in finding.get("evidence", "")
                           for finding in findings)):
            raise AssertionError("Unavailable CVE source became a PASS or lost its manual explanation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:3001", help="URL of the isolated lab")
    parser.add_argument("--host", default="lab-insecure", help="Inventory alias with the documented lab baseline")
    parser.add_argument("--scheduled-host", default="lab-scheduled", help="Separate administrator-prepared NOPASSWD lab target")
    parser.add_argument("--online", action="store_true", help="Also download the real Trivy DB and compare online/offline CVE results")
    parser.add_argument("--expect-cold-cache", action="store_true", help="Require an absent Trivy DB and verify its saved manual report before any download; never deletes a cache")
    parser.add_argument("--check-persistence", action="store_true", help="After restarting HCP, verify the reports from --output still exist")
    parser.add_argument("--output", default=".lab/verification.json", help="Save acceptance results (no password or cookie)")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in {"http", "https"} or not parts.netloc or parts.username or parts.password:
        parser.error("--url must be an HTTP(S) URL without credentials")
    origin = f"{parts.scheme}://{parts.netloc}"
    password = os.environ.get("HCP_LAB_PASSWORD", "lab-only-password")
    # This public value exists only in the disposable lab configured by
    # verify-ssh-enrollment.py.  Production callers must supply the password
    # in the UI for each on-demand sudo action; it is never stored.
    sudo_password = os.environ.get("HCP_LAB_SUDO_PASSWORD", "hcp-enrollment-fixture-password")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    protocol = {"startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": args.host, "checks": [],
                "limitations": ["Firewall apply/rollback requires a VM", "Greenbone and Dependency-Track require separate services",
                                "OpenSCAP success requires a matching datastream on a supported VM"]}
    if args.check_persistence:
        protocol = json.loads(Path(args.output).read_text())
        if protocol.get("status") != "passed" or protocol.get("host") != args.host:
            parser.error("Persistence check requires a successful earlier protocol for the same host")

    def request(endpoint, body=None, method=None, expected=200, authenticated=True):
        client = opener if authenticated else urllib.request.build_opener()
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + endpoint, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Origin": origin})
        try:
            response = client.open(req, timeout=2000)
        except urllib.error.HTTPError as error:
            response = error
        status = response.code
        raw = response.read()
        if any(secret.encode() in raw for secret in (password, sudo_password) if secret):
            raise AssertionError("HCP returned a lab credential in an API response")
        payload = json.loads(raw)
        if status != expected:
            raise AssertionError(f"{endpoint}: expected HTTP {expected}, got {status}: {payload.get('message', '')}")
        return payload

    def record(name, details=None):
        protocol["checks"].append({"name": name, "status": "passed", "details": details or {}})
        print(f"PASS {name}", flush=True)

    def run(action):
        result = request("/api/ansible/run", {"action": action, "limit": args.host,
                         "profileId": "basic_linux", "confirmAudit": True,
                         "sudoPassword": sudo_password})
        if result.get("ok") is not True:
            raise AssertionError(f"{action}: {result.get('message')}")
        return result

    def report(result, mode, snapshot=None, host=None):
        identifier = result.get("reportId")
        if not identifier:
            raise AssertionError(f"{mode}: reportId missing")
        item = request("/api/ansible/reports/" + urllib.parse.quote(identifier, safe=""))["report"]
        raw = item["raw"]
        snapshots = Path(args.output).parent / "reports"
        snapshots.mkdir(parents=True, exist_ok=True)
        (snapshots / f"{snapshot or mode}.json").write_text(json.dumps(item, ensure_ascii=False, indent=2) + "\n")
        if raw.get("inventoryHost") != (host or args.host) or raw.get("mode") != mode:
            raise AssertionError(f"{mode}: incorrect report host or mode")
        if item.get("reportTimeValid") is not True:
            raise AssertionError(f"{mode}: invalid report time")
        return item

    compose = ["docker", "compose", "-f", str(Path(__file__).resolve().parent / "docker-compose.yml")]

    def lab_command(arguments, timeout=60):
        completed = subprocess.run(compose + arguments, text=True, capture_output=True, timeout=timeout)
        if completed.returncode:
            raise AssertionError("Native lab command failed: " + completed.stderr[-1000:])
        return completed.stdout

    def scheduled(task, host, suffix=""):
        # Use the installed production CLI as the same unprivileged user as the
        # systemd units. The schedule key comes only from the lab container env.
        completed = subprocess.run(compose + ["exec", "--user", "node", "-T",
            "-e", "HCP_SCHEDULE_TASKS=" + task,
            "-e", "HCP_SCHEDULE_PROFILE=basic_linux",
            "-e", "HCP_SCHEDULE_LIMIT=" + host,
            "-e", "HCP_SCHEDULE_DEEP_LIMIT=" + host,
            "hcp", "/usr/local/bin/hcp-scheduled-audit"],
            text=True, capture_output=True, timeout=2000)
        if any(secret in completed.stdout + completed.stderr for secret in (password, sudo_password) if secret):
            raise AssertionError("Scheduled CLI exposed a lab credential")
        try:
            payload, result = verify_scheduled_response(completed, host)
        except (AssertionError, ValueError) as error:
            raise AssertionError(f"Scheduled {task}: {error}; stderr={completed.stderr[-1500:]}") from error
        snapshots = Path(args.output).parent / "reports"
        snapshots.mkdir(parents=True, exist_ok=True)
        (snapshots / f"scheduled-{task}{suffix}-cli.json").write_text(json.dumps({
            "task": task, "host": host, "exitCode": completed.returncode, "response": payload,
        }, ensure_ascii=False, indent=2) + "\n")
        return payload, result, completed.returncode

    original_mode = None
    scheduled_binding = None
    scheduled_facts = None
    failures = []

    @contextlib.contextmanager
    def independent_check(name):
        try:
            yield
        except Exception as error:
            message = f"{name}: {error}"
            failures.append(message)
            protocol["checks"].append({"name": name, "status": "failed", "error": str(error)})
            print(f"FAIL {message}", file=sys.stderr, flush=True)

    try:
        request("/api/ansible/hosts", expected=401, authenticated=False)
        record("Unauthenticated control API is blocked")
        request("/api/ansible/auth/login", {"password": password})
        health = request("/api/ansible/health")
        if not health.get("ansibleInstalled") or not health.get("inventoryReady"):
            raise AssertionError("Ansible or inventory is not ready")
        hosts = request("/api/ansible/hosts")["hosts"]
        if args.host not in {host["alias"] for host in hosts}:
            raise AssertionError("Lab host missing from inventory")
        record("Login, Ansible health and inventory")
        if args.check_persistence:
            identifiers = {}
            for check in protocol["checks"]:
                details = check.get("details", {})
                for key, value in details.items():
                    if key in {"reportId", "onlineReport", "offlineReport", "packageReportId", "vulnerabilityReportId"}:
                        identifiers[value] = details.get("hostAlias", args.host)
            if not identifiers:
                raise AssertionError("Earlier protocol contains no reports to verify")
            for identifier, expected_host in identifiers.items():
                stored = request("/api/ansible/reports/" + urllib.parse.quote(identifier, safe=""))["report"]
                if stored.get("inventoryHost") != expected_host:
                    raise AssertionError("Persisted report lost host identity")
            if request("/api/settings/vulnerability-data")["database"]["mode"] != protocol["databaseModeBefore"]:
                raise AssertionError("Database selection did not survive restart")
            record("Reports, host and database selection survive HCP restart", {"reports": len(identifiers)})
            return 0
        run("ping")
        record("Real SSH / Ansible ping")
        with independent_check("Host readiness through real SSH"):
            host = next(item for item in hosts if item["alias"] == args.host)
            preflight = request("/api/ansible/hosts/preflight", {
                "alias": host["alias"], "address": host["address"], "user": host["user"],
                "port": host.get("port", 22), "become": host.get("become", True),
                "sudoPassword": sudo_password,
            })
            if not preflight.get("ok") or not preflight.get("readiness"):
                raise AssertionError(f"Readiness collection failed: {preflight.get('readinessError') or preflight.get('checks')}")
            readiness = preflight["readiness"]
            checks = {item["id"]: item for item in readiness["checks"]}
            if checks["packages"]["state"] != "ready" or checks["openscap"]["state"] != "needs_setup":
                raise AssertionError("Readiness incorrectly classified package or SCAP prerequisites")
            record("Host readiness through real SSH", readiness)
        with independent_check("Scheduled target readiness and modern runtime through real SSH"):
            scheduled_host = next((host for host in hosts if host["alias"] == args.scheduled_host), None)
            if (not scheduled_host or scheduled_host.get("address") != "lab-scheduled-target"
                    or scheduled_host.get("user") != "lab" or scheduled_host.get("credentialId")
                    or args.scheduled_host == args.host):
                raise AssertionError("The separate preprovisioned scheduled fixture is missing; start a fresh lab with its seed inventory")
            observed = json.loads(lab_command(["exec", "--user", "lab", "-T", "lab-scheduled-target",
                "sudo", "-n", "/usr/bin/python3", "-c",
                'import json, os, sys; print(json.dumps({"pythonVersion": ".".join(map(str, sys.version_info[:3])), "uid": os.geteuid()}))']))
            preflight = request("/api/ansible/hosts/preflight", {
                "alias": args.scheduled_host, "address": scheduled_host["address"],
                "user": scheduled_host["user"], "port": scheduled_host.get("port", 22), "become": True,
            })
            scheduled_facts = preflight.get("facts", {})
            if (observed.get("uid") != 0 or not preflight.get("ok")
                    or preflight.get("checks", {}).get("sudo", {}).get("state") != "passed"
                    or scheduled_facts.get("pythonVersion") != observed.get("pythonVersion")
                    or scheduled_facts.get("configuredPython") != "/usr/bin/python3"
                    or scheduled_facts.get("ansibleRuntime") != "modern"
                    or scheduled_facts.get("ansibleCoreVersion") != "2.21.5"
                    or preflight.get("assetBinding", {}).get("status") != "verified"):
                raise AssertionError("Scheduled target lacks verified identity, native passwordless sudo or the selected modern runtime")
            scheduled_binding = preflight["assetBinding"]
            record("Scheduled target readiness and modern runtime through real SSH", {
                "hostAlias": args.scheduled_host, "facts": scheduled_facts,
                "nativeSudoUid": observed["uid"], "assetBindingStatus": scheduled_binding["status"],
            })
        with independent_check("On-demand sudo is rejected by the real scheduler without storing a password"):
            enrolled = next(host for host in hosts if host["alias"] == args.host)
            if enrolled.get("sudoMode") != "on_demand":
                raise AssertionError("Run verify-ssh-enrollment.py before the scheduled on-demand denial control")
            for task in ("agentless", "packages"):
                _, denied, exit_code = scheduled(task, args.host, "-on-demand-denied")
                if (denied.get("errorCode") != "sudo_password_required" or not denied.get("error")
                        or any(denied.get(key) for key in ("reportId", "packageReportId", "vulnerabilityReportId"))):
                    raise AssertionError("Scheduler did not reject the on-demand target before collecting a report")
                record("Scheduled " + task + " rejects on-demand sudo before collection", {
                    "hostAlias": args.host, "errorCode": denied["errorCode"], "exitCode": exit_code,
                })
        facts = report(run("collectFacts"), "facts")
        if not facts["raw"].get("os"):
            raise AssertionError("Facts did not identify an operating system")
        record("Host facts", {"reportId": facts["id"], "os": facts["raw"]["os"]})
        with independent_check('Known SSH configuration deviations'):
            baseline = report(run("agentlessAudit"), "agentless")
            verify_known_ssh_deviations(baseline)
            record("Known SSH configuration deviations", {"reportId": baseline["id"]})
        with independent_check("Production scheduled agentless collection, publication and partial exit"):
            if not scheduled_binding:
                raise AssertionError("The independent scheduled preflight did not complete")
            payload, result, exit_code = scheduled("agentless", args.scheduled_host)
            if result.get("error"):
                raise AssertionError("Scheduled agentless collector failed: " + result["error"])
            item = report(result, "agentless", "scheduled-agentless", args.scheduled_host)
            verify_scheduled_binding(item, args.scheduled_host, scheduled_binding)
            verify_known_ssh_deviations(item)
            scanner = item["raw"].get("scanner", {})
            if (scanner.get("source") != "agentless"
                    or result.get("partial") is not item.get("partial")
                    or scanner.get("partial") is not item.get("partial")
                    or bool(scanner.get("incompleteChecks")) is not item.get("partial")):
                raise AssertionError("Scheduled agentless API/CLI lost the real collector's incomplete checks")
            record("Production scheduled agentless collection, publication and partial exit", {
                "hostAlias": args.scheduled_host, "reportId": item["id"], "scheduleRunId": payload["reportRunId"],
                "exitCode": exit_code, "partial": item["partial"], "findings": len(item["findings"]),
                "incompleteChecks": scanner["incompleteChecks"], "assetBindingStatus": "verified",
                "facts": scheduled_facts,
            })
        with independent_check('Real ssh-audit negotiation'):
            ssh = report(run("sshCryptoAudit"), "ssh-audit")
            if ssh["raw"].get("scanner", {}).get("available") is not True or ssh["raw"]["scanner"].get("partial"):
                raise AssertionError(f"ssh-audit did not return complete scanner output: {ssh['findings']}")
            record("Real ssh-audit negotiation", {"reportId": ssh["id"]})
        with independent_check('Real Nmap scan'):
            network = report(run("networkPortScan"), "nmap")
            if network["raw"].get("scanner", {}).get("partial") or not network["raw"]["scanner"].get("available"):
                raise AssertionError("Nmap did not return complete scanner output")
            for port in (22, 23):
                if not any(f.get("id") == f"nmap_open_tcp_{port}"
                           for f in network["findings"]):
                    raise AssertionError(f"Nmap did not detect open TCP port {port}")
            record("Real Nmap observes TCP ports 22 and 23", {"reportId": network["id"]})
        with independent_check('Real temporary Lynis run'):
            lynis = report(run("lynisTemporaryAudit"), "lynis")
            if not lynis["raw"].get("scanner", {}).get("available") or lynis["raw"]["scanner"].get("partial"):
                raise AssertionError(f"Lynis did not return a complete scanner report: {lynis['raw'].get('scanner')}")
            record("Real temporary Lynis run", {"reportId": lynis["id"]})
        original_mode = request("/api/settings/vulnerability-data")["database"]["mode"]
        protocol["databaseModeBefore"] = original_mode
        # Start offline even when reusing a lab whose last saved mode was online.
        # A missing DB must produce a stored manual report before any download;
        # CI requires this cold-cache control rather than silently skipping it.
        request("/api/settings/vulnerability-data", {"mode": "offline"}, method="PATCH")
        with independent_check('Package inventory and Trivy'):
            packages = report(run("packageInventory"), "packages")
            if not packages["raw"].get("packages") or packages["raw"].get("packageInventory", {}).get("error"):
                raise AssertionError("Package inventory is empty or incomplete")

            def cve_scan(snapshot=None):
                payload = request("/api/ansible/vulnerabilities/check", {"hostAlias": args.host, "reportId": packages["id"]})
                item = report(payload, "vulnerabilities", snapshot)
                if item["score"] is not None:
                    raise AssertionError("CVE report invents a security percentage")
                return payload, item

            def verify_cve_evidence(payload, item, source_packages=None):
                source_packages = packages if source_packages is None else source_packages
                raw = item["raw"]
                scan = raw["vulnerabilityScan"]
                coverage = scan["coverage"]
                provenance = scan["packageProvenance"]
                evidence = scan["sourceEvidence"]
                count = len(source_packages["raw"]["packages"])
                if not raw.get("scanner", {}).get("available") or coverage["scannedPackages"] != count or coverage["inventoryPackages"] != count:
                    raise AssertionError("Native Trivy did not account for every collected package")
                if scan["databaseFreshness"]["status"] != "fresh" or evidence["status"] != "unchanged" or evidence["before"] != evidence["after"]:
                    raise AssertionError("Native Trivy source freshness or byte identity is unproven")
                if any(not isinstance(pkg.get("maintainer"), str) or not isinstance(pkg.get("origin"), str) for pkg in source_packages["raw"]["packages"]):
                    raise AssertionError("Collector lost installed package provenance observations")
                uncertain = provenance["unknown"] + provenance["third-party"]
                if provenance["cryptographicallyVerified"] or provenance["distribution-maintainer"] + uncertain != count:
                    raise AssertionError("Package provenance was dropped or presented as a signature attestation")
                # Personal maintainer addresses can belong to real Debian
                # packages; the conservative heuristic must expose uncertainty.
                # No other incomplete condition is accepted by this fixture.
                if bool(payload.get("partial")) != bool(uncertain) or item["partial"] != bool(uncertain) or coverage["complete"] != (not uncertain):
                    raise AssertionError("Native Trivy completeness does not match observed provenance")
                if len(coverage["reasons"]) != (1 if uncertain else 0):
                    raise AssertionError("Native Trivy has an additional unexplained incomplete condition")
                if uncertain and any(finding["id"] == "trivy_no_known_vulnerabilities" for finding in item["findings"]):
                    raise AssertionError("Unknown package origin became an empty successful CVE verdict")
                for finding in item["findings"]:
                    if "applicability=unverified" in (finding.get("evidence") or "") and finding["status"] != "manual":
                        raise AssertionError("Unverified third-party applicability became a definite finding")

            freshness = request("/api/settings/vulnerability-data")["freshness"]["status"]
            if args.expect_cold_cache and freshness != "missing":
                raise AssertionError("Cold-cache control requires an absent Trivy DB; use a fresh disposable lab without deleting an existing cache")
            if not args.online or freshness == "missing":
                offline, offline_report = cve_scan("vulnerabilities-offline-initial")
                if freshness == "fresh":
                    verify_cve_evidence(offline, offline_report)
                    record("Existing offline Trivy cache produces verifiable scan evidence", {"reportId": offline_report["id"]})
                else:
                    verify_unavailable_cve_report(offline, offline_report, packages, freshness)
                    record("Unavailable offline Trivy database produces a saved manual report without a PASS", {
                        "reportId": offline_report["id"], "packageReport": packages["id"], "databaseFreshness": freshness,
                        "checkedPackages": 0, "coverageComplete": False,
                    })

            if args.online:
                # Download once, then prove both modes consume the same bytes.
                request("/api/settings/vulnerability-data", {"mode": "online"}, method="PATCH")
                refreshed = request("/api/settings/vulnerability-data", method="POST")
                if refreshed.get("freshness", {}).get("status") != "fresh":
                    raise AssertionError(f"Trivy database refresh did not confirm freshness: {refreshed.get('freshness')}")
                online, online_report = cve_scan()
                verify_cve_evidence(online, online_report)
                request("/api/settings/vulnerability-data", {"mode": "offline"}, method="PATCH")
                offline, offline_report = cve_scan()
                verify_cve_evidence(offline, offline_report)
                def findings(item):
                    return sorted((f["id"], f["status"], f["risk"]) for f in item["findings"] if f.get("source") == "trivy")
                if findings(online_report) != findings(offline_report):
                    raise AssertionError("Online/offline findings differ for the same inventory and cached DB")
                for source in ("database", "metadata", "engine"):
                    if online_report["raw"]["vulnerabilityScan"]["sourceEvidence"]["before"][source]["sha256"] != offline_report["raw"]["vulnerabilityScan"]["sourceEvidence"]["before"][source]["sha256"]:
                        raise AssertionError("Online/offline native scans consumed different source bytes")
                record("Real Trivy DB: online and cached offline results match", {"onlineReport": online_report["id"], "offlineReport": offline_report["id"], "packageProvenance": online_report["raw"]["vulnerabilityScan"]["packageProvenance"], "partial": online_report["partial"]})
            if request("/api/settings/vulnerability-data")["freshness"]["status"] == "fresh":
                with independent_check("Production scheduled inventory and native Trivy preserve complete evidence"):
                    if not scheduled_binding:
                        raise AssertionError("The independent scheduled preflight did not complete")
                    payload, result, exit_code = scheduled("packages", args.scheduled_host)
                    if result.get("error") or result.get("dependencyTrackStatus") != "skipped":
                        raise AssertionError("Scheduled inventory/Trivy failed or unexpectedly used Dependency-Track")
                    saved_packages = report({"reportId": result.get("packageReportId")}, "packages", "scheduled-packages", args.scheduled_host)
                    saved_scan = report({"reportId": result.get("vulnerabilityReportId")}, "vulnerabilities", "scheduled-vulnerabilities", args.scheduled_host)
                    for item in (saved_packages, saved_scan):
                        verify_scheduled_binding(item, args.scheduled_host, scheduled_binding)
                    native_packages = lab_command(["exec", "-T", "lab-scheduled-target", "dpkg-query", "--show",
                        "--showformat=${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\n"])
                    verify_native_package_snapshot(saved_packages, native_packages)
                    verify_cve_evidence(payload, saved_scan, saved_packages)
                    scan = saved_scan["raw"]["vulnerabilityScan"]
                    if (scan.get("sourcePackageReportId") != saved_packages["id"]
                            or result.get("partial") is not saved_scan.get("partial")
                            or saved_scan.get("score") is not None):
                        raise AssertionError("Scheduled CVE report lost its source inventory, partial status or unscored assessment")
                    record("Production scheduled inventory and native Trivy preserve complete evidence", {
                        "hostAlias": args.scheduled_host, "packageReportId": saved_packages["id"],
                        "vulnerabilityReportId": saved_scan["id"], "scheduleRunId": payload["reportRunId"],
                        "exitCode": exit_code, "partial": saved_scan["partial"],
                        "packageCount": len(saved_packages["raw"]["packages"]),
                        "checkedPackages": scan["checkedPackages"], "coverage": scan["coverage"],
                        "packageProvenance": scan["packageProvenance"], "assetBindingStatus": "verified",
                        "facts": scheduled_facts,
                    })
            elif args.online:
                raise AssertionError("Scheduled package acceptance requires the fresh DB established by the online control")
            else:
                protocol["limitations"].append("Scheduled native Trivy acceptance requires --online or an already fresh cache; the cold-cache control was retained")
        with independent_check('Unprepared OpenSCAP handling'):
            unprepared = request("/api/ansible/run", {
                "action": "openScapAudit", "limit": args.host,
                "profileId": "basic_linux", "confirmAudit": True,
                "sudoPassword": sudo_password,
            }, expected=400)
            if (unprepared.get("ok") is not False
                    or unprepared.get("error") != "openscap_profile_missing"
                    or unprepared.get("reportId")):
                raise AssertionError("OpenSCAP without an assigned profile must be rejected before a scan starts")
            record("Unconfigured OpenSCAP is rejected before starting a scan")
        if failures:
            raise AssertionError("; ".join(failures))
        protocol["status"] = "passed"
    except Exception as error:
        protocol["status"] = "failed"
        protocol["error"] = str(error)
        print(f"FAIL {error}", file=sys.stderr, flush=True)
    finally:
        if original_mode is not None:
            try:
                request("/api/settings/vulnerability-data", {"mode": original_mode}, method="PATCH")
            except Exception as error:
                protocol["status"] = "failed"
                protocol["restoreError"] = str(error)
        protocol["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")
    return 0 if protocol["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
