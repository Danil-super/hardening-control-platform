#!/usr/bin/env python3
"""Acceptance checks against the running, disposable HCP Docker laboratory."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:3001", help="URL of the isolated lab")
    parser.add_argument("--host", default="lab-insecure", help="Inventory alias with the documented lab baseline")
    parser.add_argument("--online", action="store_true", help="Also download the real Trivy DB and compare online/offline CVE results")
    parser.add_argument("--check-persistence", action="store_true", help="After restarting HCP, verify the reports from --output still exist")
    parser.add_argument("--output", default=".lab/verification.json", help="Save acceptance results (no password or cookie)")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in {"http", "https"} or not parts.netloc or parts.username or parts.password:
        parser.error("--url must be an HTTP(S) URL without credentials")
    origin = f"{parts.scheme}://{parts.netloc}"
    password = os.environ.get("HCP_LAB_PASSWORD", "lab-only-password")
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
        payload = json.loads(response.read())
        if status != expected:
            raise AssertionError(f"{endpoint}: expected HTTP {expected}, got {status}: {payload.get('message', '')}")
        return payload

    def record(name, details=None):
        protocol["checks"].append({"name": name, "status": "passed", "details": details or {}})
        print(f"PASS {name}", flush=True)

    def run(action):
        result = request("/api/ansible/run", {"action": action, "limit": args.host,
                         "profileId": "basic_linux", "confirmAudit": True})
        if result.get("ok") is not True:
            raise AssertionError(f"{action}: {result.get('message')}")
        return result

    def report(result, mode):
        identifier = result.get("reportId")
        if not identifier:
            raise AssertionError(f"{mode}: reportId missing")
        item = request("/api/ansible/reports/" + urllib.parse.quote(identifier, safe=""))["report"]
        raw = item["raw"]
        if raw.get("inventoryHost") != args.host or raw.get("mode") != mode:
            raise AssertionError(f"{mode}: incorrect report host or mode")
        if item.get("reportTimeValid") is not True:
            raise AssertionError(f"{mode}: invalid report time")
        return item

    original_mode = None
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
            identifiers = set()
            for check in protocol["checks"]:
                for key, value in check.get("details", {}).items():
                    if key in {"reportId", "onlineReport", "offlineReport"}:
                        identifiers.add(value)
            if not identifiers:
                raise AssertionError("Earlier protocol contains no reports to verify")
            for identifier in identifiers:
                stored = request("/api/ansible/reports/" + urllib.parse.quote(identifier, safe=""))["report"]
                if stored.get("inventoryHost") != args.host:
                    raise AssertionError("Persisted report lost host identity")
            if request("/api/settings/vulnerability-data")["database"]["mode"] != protocol["databaseModeBefore"]:
                raise AssertionError("Database selection did not survive restart")
            record("Reports, host and database selection survive HCP restart", {"reports": len(identifiers)})
            return 0
        run("ping")
        record("Real SSH / Ansible ping")
        facts = report(run("collectFacts"), "facts")
        if not facts["raw"].get("os"):
            raise AssertionError("Facts did not identify an operating system")
        record("Host facts", {"reportId": facts["id"], "os": facts["raw"]["os"]})
        baseline = report(run("agentlessAudit"), "agentless")
        failed = [finding for finding in baseline["findings"] if finding.get("status") == "failed"]
        for evidence in ("PermitRootLogin=yes", "MaxAuthTries=8"):
            if not any(evidence in finding.get("evidence", "") for finding in failed):
                raise AssertionError(f"Known lab deviation was not detected: {evidence}")
        record("Known SSH configuration deviations", {"reportId": baseline["id"]})
        ssh = report(run("sshCryptoAudit"), "ssh-audit")
        if ssh["raw"].get("scanner", {}).get("available") is not True or ssh["raw"]["scanner"].get("partial"):
            raise AssertionError("ssh-audit did not return complete scanner output")
        record("Real ssh-audit negotiation", {"reportId": ssh["id"]})
        network = report(run("networkPortScan"), "nmap")
        if network["raw"].get("scanner", {}).get("partial") or not network["raw"]["scanner"].get("available"):
            raise AssertionError("Nmap did not return complete scanner output")
        for port in (22, 23):
            if not any(f.get("id") == f"nmap_open_tcp_{port}"
                       for f in network["findings"]):
                raise AssertionError(f"Nmap did not detect open TCP port {port}")
        record("Real Nmap observes TCP ports 22 and 23", {"reportId": network["id"]})
        lynis = report(run("lynisTemporaryAudit"), "lynis")
        if not lynis["raw"].get("scanner", {}).get("available") or lynis["raw"]["scanner"].get("partial"):
            raise AssertionError("Lynis did not return a complete scanner report")
        record("Real temporary Lynis run", {"reportId": lynis["id"]})
        original_mode = request("/api/settings/vulnerability-data")["database"]["mode"]
        protocol["databaseModeBefore"] = original_mode
        request("/api/settings/vulnerability-data", {"mode": "offline"}, method="PATCH")
        packages = report(run("packageInventory"), "packages")
        if not packages["raw"].get("packages") or packages["raw"].get("packageInventory", {}).get("error"):
            raise AssertionError("Package inventory is empty or incomplete")

        def cve_scan():
            payload = request("/api/ansible/vulnerabilities/check", {"hostAlias": args.host, "reportId": packages["id"]})
            item = report(payload, "vulnerabilities")
            if item["score"] is not None:
                raise AssertionError("CVE report invents a security percentage")
            return payload, item

        initial, initial_report = cve_scan()
        freshness = initial_report["raw"]["vulnerabilityScan"]["databaseFreshness"]
        if freshness["status"] != "fresh" and not initial_report["partial"]:
            raise AssertionError("Missing/stale/unknown DB was treated as a complete scan")
        record("Offline CVE result preserves database availability", {"reportId": initial_report["id"], "database": freshness["status"]})
        if args.online:
            request("/api/settings/vulnerability-data", {"mode": "online"}, method="PATCH")
            online, online_report = cve_scan()
            if online.get("partial") or online_report["partial"]:
                raise AssertionError(f"Live Trivy online scan is incomplete: {online.get('message')}")
            request("/api/settings/vulnerability-data", {"mode": "offline"}, method="PATCH")
            offline, offline_report = cve_scan()
            if offline.get("partial") or offline_report["partial"]:
                raise AssertionError(f"Cached Trivy offline scan is incomplete: {offline.get('message')}")
            def findings(item):
                return sorted((f["id"], f["status"], f["risk"]) for f in item["findings"] if f.get("source") == "trivy")
            if findings(online_report) != findings(offline_report):
                raise AssertionError("Online/offline findings differ for the same inventory and cached DB")
            record("Real Trivy DB: online and cached offline results match", {"onlineReport": online_report["id"], "offlineReport": offline_report["id"]})
        unprepared = run("openScapAudit")
        unprepared_report = report(unprepared, "openscap")
        if not unprepared.get("partial") or not unprepared_report["partial"]:
            raise AssertionError("Unprepared OpenSCAP target was treated as a complete audit")
        record("Unprepared OpenSCAP is explicitly incomplete", {"reportId": unprepared_report["id"]})
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
