#!/usr/bin/env python3
"""Live Greenbone/GMP -> native XML -> production HCP parser acceptance.

Creates a NEW isolated stack and exactly one synthetic HTTP target. No address
argument, published port, host networking, LAN discovery or existing database
is accepted. The selected official VT detects the intentionally enabled HTTP
TRACE method; its normal scanner dependencies are enabled, safe_checks is on.
This verifies a real network finding, not a full host/OS or CVE coverage claim.

Linux Docker/Compose host, Python 3.10+ and PyYAML 6.0.3 are required. Docker's
daemon downloads images, while all running containers use an internal network.
First feed ingestion can take an hour or more. Failures keep evidence and exit
nonzero; no unavailable scanner/feed is converted into a passed/skipped check.
"""

import argparse
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET

import yaml


REPO = Path(__file__).resolve().parents[2]
UPSTREAM_COMMIT = "173b0a14e4c4032ee84b0c37f6a8fea84788f14f"
UPSTREAM_URL = ("https://raw.githubusercontent.com/greenbone/docs/" + UPSTREAM_COMMIT
                + "/src/_static/compose.yaml")
UPSTREAM_SHA256 = "5b5117a7c200491de13bc7b79c97dc858c016c51017982d8f1de7ca077c1a868"
FULL_FAST_ID = "daba56c8-73ec-11df-a475-002264764cea"
# The live feed is authoritative: its name/family/metadata must also match.
TRACE_OID = "1.3.6.1.4.1.25623.1.0.11213"

# GMP is a stream of XML documents over the manager's private Unix socket.
# Use the official gvm-tools image's Python runtime. Credentials go through
# stdin; neither shell interpolation nor command-line password arguments occur.
GMP_CLIENT = r'''
import json, socket, sys, xml.etree.ElementTree as ET
payload = json.load(sys.stdin)
def exchange(sock, document):
    sock.sendall(document.encode())
    parser = ET.XMLPullParser(events=("start", "end"))
    depth = 0
    size = 0
    while True:
        part = sock.recv(65536)
        if not part:
            raise RuntimeError("GMP closed before a complete XML response")
        size += len(part)
        if size > 20 * 1024 * 1024:
            raise RuntimeError("GMP response exceeds HCP's 20 MiB import limit")
        parser.feed(part)
        for event, element in parser.read_events():
            depth += 1 if event == "start" else -1
            if event == "end" and depth == 0:
                if not element.get("status", "").startswith("2"):
                    raise RuntimeError(element.tag + ": " + element.get("status", "") + " " + element.get("status_text", ""))
                return element
auth = ET.Element("authenticate")
credentials = ET.SubElement(auth, "credentials")
ET.SubElement(credentials, "username").text = "admin"
ET.SubElement(credentials, "password").text = payload["password"]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(90)
    sock.connect("/run/gvmd/gvmd.sock")
    if payload.get("password") is not None:
        exchange(sock, ET.tostring(auth, encoding="unicode"))
    result = exchange(sock, payload["xml"])
print(ET.tostring(result, encoding="unicode"))
'''

HTTP_TARGET = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    server_version = "HCP-Live-TRACE-Acceptance/1.0"
    def do_GET(self):
        data = b"Owned disposable HCP test target. HTTP TRACE is intentionally enabled.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()
    def do_TRACE(self):
        data = (self.requestline + "\r\n" + str(self.headers) + "\r\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
'''


def element(name, text=None, **attributes):
    result = ET.Element(name, attributes)
    result.text = text
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=".lab/greenbone-acceptance")
    parser.add_argument("--timeout-minutes", type=int, default=85)
    parser.add_argument("--include-advisory-feeds", action="store_true",
                        help="Also import full SCAP/CERT advisory databases; not needed for the selected HTTP VT")
    args = parser.parse_args()
    if not 20 <= args.timeout_minutes <= 180:
        parser.error("Timeout must be between 20 and 180 minutes")
    if not shutil.which("docker") or not sys.platform.startswith("linux"):
        parser.error("A Linux Docker/Compose host is required")
    output = (REPO / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    compose_file = output / "compose.json"
    if compose_file.exists():
        parser.error("Output already contains a stack: clean it up and choose a fresh output directory")
    deadline = time.monotonic() + args.timeout_minutes * 60
    project = "hcp-greenbone-acceptance-" + uuid.uuid4().hex[:10]
    password = secrets.token_urlsafe(32)
    credentials = [password]
    protocol = {
        "startedAt": datetime.now(timezone.utc).isoformat(), "status": "running",
        "scope": "Actual official HTTP TRACE VT against one disposable container, followed by the production HCP XML parser",
        "targetIsSynthetic": True, "reportIsFixture": False, "fullHostAudit": False,
        "externalRuntimeNetwork": False, "upstreamComposeCommit": UPSTREAM_COMMIT,
        "advisoryFeedsIncluded": args.include_advisory_feeds,
        "upstreamComposeSha256": UPSTREAM_SHA256, "checks": [], "stage": "preflight",
        "limitations": ["No Astra compatibility or complete OS/CVE coverage is asserted",
                        "Only the selected safe VT and its scanner dependencies run",
                        "GMP orchestration belongs to this acceptance script; the HCP UI still imports XML"],
    }
    compose = ["docker", "compose", "-f", str(compose_file)]

    def redact(value):
        for credential in credentials:
            value = value.replace(credential, "[REDACTED]")
        return value

    def save():
        (output / "protocol.json").write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n")

    def remaining(maximum):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"Live acceptance exceeded {args.timeout_minutes} minutes during {protocol['stage']}")
        return min(left, maximum)

    def command(argv, timeout=120, check=True, **kwargs):
        result = subprocess.run(argv, cwd=REPO, capture_output=True, text=True,
                                timeout=remaining(timeout), **kwargs)
        if check and result.returncode:
            raise RuntimeError(redact(f"{argv[0]} exited {result.returncode}: {result.stderr[-3000:]}"))
        return result.stdout

    def record(name, **details):
        protocol["checks"].append({"name": name, "status": "passed", **details})
        save()
        print("PASS " + name, flush=True)

    def stage(name):
        protocol["stage"] = name
        save()
        print("STAGE " + name, flush=True)

    def gmp(request, *, authenticate=True):
        document = request if isinstance(request, str) else ET.tostring(request, encoding="unicode")
        result = command(compose + ["exec", "-T", "gvm-tools", "python3", "-c", GMP_CLIENT],
                         input=json.dumps({"password": password if authenticate else None, "xml": document}), timeout=110)
        return ET.fromstring(result)

    def wait_for(name, probe, budget, diagnostics=None):
        until = time.monotonic() + remaining(budget)
        last_error = "not ready"
        attempts = 0
        while time.monotonic() < until:
            try:
                result = probe()
                if result is not None and result is not False:
                    return result
            except (RuntimeError, OSError, TimeoutError, ET.ParseError) as error:
                last_error = redact(str(error))[-1200:]
            attempts += 1
            if attempts % 3 == 1:
                print(f"WAIT {name}: {last_error}", flush=True)
                if diagnostics:
                    diagnostics()
            time.sleep(min(20, max(0, until - time.monotonic())))
        raise TimeoutError(f"{name} did not become ready: {last_error}")

    try:
        info = json.loads(command(["docker", "info", "--format", "{{json .}}"], timeout=30))
        docker_root = info.get("DockerRootDir", "/var/lib/docker")
        disk = shutil.disk_usage(docker_root if Path(docker_root).exists() else output)
        memory = int(info.get("MemTotal", 0))
        protocol["resources"] = {"dockerMemoryBytes": memory, "freeDiskBytes": disk.free,
                                  "cpus": info.get("NCPU")}
        if memory < 4 * 1024**3 or disk.free < 20 * 1024**3:
            raise RuntimeError("Greenbone minimum requires 4 GiB RAM and 20 GiB free disk; recommended 8 GiB/60 GiB")
        record("Linux Docker resources meet published minimum")
        stage("download pinned official Compose definition")
        with urllib.request.urlopen(UPSTREAM_URL, timeout=30) as response:
            upstream = response.read(1024 * 1024)
        if hashlib.sha256(upstream).hexdigest() != UPSTREAM_SHA256:
            raise RuntimeError("Pinned official Compose checksum mismatch")
        stack = yaml.safe_load(upstream)
        stack["name"] = project
        stack["networks"] = {"default": {"internal": True}}
        for name in ("gsa", "gsad", "gvm-config", "nginx", "openvas"):
            del stack["services"][name]
        # This acceptance establishes a real network VT and HCP import. The
        # complete SCAP/CERT advisory mirror is an independent, much larger
        # workload (the live runner spent 40 min importing CVE tables). Keep
        # the official NASL/Notus feed and data objects unchanged; no VT/report
        # is manufactured. Full advisory ingestion remains explicitly opt-in.
        if not args.include_advisory_feeds:
            for name in ("scap-data", "cert-bund-data", "dfn-cert-data"):
                del stack["services"][name]
                for service in stack["services"].values():
                    dependencies = service.get("depends_on", {})
                    if isinstance(dependencies, dict):
                        dependencies.pop(name, None)
                    else:
                        service["depends_on"] = [dependency for dependency in dependencies if dependency != name]
            protocol["limitations"].append("SCAP/CERT advisory databases are excluded from this network-VT acceptance")
        for service in stack["services"].values():
            if service.get("ports") or service.get("network_mode") or service.get("privileged"):
                raise RuntimeError("Pinned upstream unexpectedly publishes a port or uses host/privileged networking")
        stack["services"]["gvm-tools"]["entrypoint"] = ["python3", "-c", "import time; time.sleep(14400)"]
        stack["services"]["target"] = {
            "image": "python:3.12-slim-bookworm", "entrypoint": ["python3", "-u", "-c", HTTP_TARGET],
            "read_only": True, "cap_drop": ["ALL"], "cap_add": ["NET_BIND_SERVICE"],
            "security_opt": ["no-new-privileges:true"], "mem_limit": "128m", "cpus": 0.5,
        }
        compose_file.write_text(json.dumps(stack, indent=2) + "\n")
        compose_file.chmod(0o600)
        command(compose + ["config", "--quiet"], timeout=30)
        record("Pinned official stack adapted to internal network with no published ports")
        stage("pull actual scanner and feed images")
        command(compose + ["pull", "--quiet"], timeout=1800)
        images = []
        for image_name in sorted({service["image"] for service in stack["services"].values()}):
            details = json.loads(command(["docker", "image", "inspect", image_name]))[0]
            images.append({"reference": image_name, "id": details["Id"], "digests": details.get("RepoDigests", [])})
            digests = details.get("RepoDigests", [])
            if not digests:
                raise RuntimeError("Pulled image has no immutable repository digest: " + image_name)
            for service in stack["services"].values():
                if service["image"] == image_name:
                    service["image"] = digests[0]
        # Freeze the exact pulled images for all subsequent start/exec/cleanup.
        compose_file.write_text(json.dumps(stack, indent=2) + "\n")
        (output / "images.json").write_text(json.dumps(images, indent=2) + "\n")
        record("Scanner and feed image digests captured and locked", imageCount=len(images))
        stage("start services and import feeds")
        command(compose + ["up", "-d"], timeout=1800)

        def bootstrap_diagnostics():
            logs = redact(command(compose + ["logs", "--no-color", "--tail", "30", "gvmd", "pg-gvm"],
                                  timeout=30, check=False))
            states = command(compose + ["ps", "-a", "--format", "json", "gvmd", "pg-gvm", "gvm-tools", "ospd-openvas"],
                             timeout=30, check=False)
            protocol["bootstrapDiagnostics"] = {"logs": logs[-6000:], "states": states[-6000:]}
            save()
            print("BOOTSTRAP " + logs[-3000:], flush=True)
            if "Starting gvmd failed" in logs:
                raise ValueError("The manager startup script reported a terminal daemon failure; see bootstrap diagnostics")

        # start-gvmd migrates the schema and creates its initial user before
        # opening GMP. Running a second modifying gvmd CLI process during that
        # migration can race the bootstrap. First probe only get_version on
        # the real listener; never interpret an SQL/auth failure as no user.
        wait_for("manager listener after database bootstrap",
                 lambda: gmp("<get_version/>", authenticate=False), 900, bootstrap_diagnostics)
        gvmd_cli = compose + ["exec", "-T", "-u", "gvmd", "gvmd", "gvmd"]
        users_text = command(gvmd_cli + ["--get-users", "--verbose"], timeout=100)
        users = {}
        for line in users_text.splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r"(.+?)\s+([0-9a-fA-F-]{36})", line.strip())
            if not match:
                raise RuntimeError("gvmd --get-users returned an unrecognized user record")
            users[match[1]] = str(uuid.UUID(match[2]))
        created_admin = "admin" not in users
        # This is exclusively the brand-new disposable manager. Creating its
        # account is allowed only after a successful user listing proves that
        # it is absent; a database/permission error never enters this branch.
        if created_admin:
            command(gvmd_cli + ["--create-user=admin", "--password=" + password], timeout=100)
            users_text = command(gvmd_cli + ["--get-users", "--verbose"], timeout=100)
            admin_match = re.search(r"^admin\s+([0-9a-fA-F-]{36})\s*$", users_text, re.MULTILINE)
            if not admin_match:
                raise RuntimeError("New administrator is not present after successful account creation")
            admin_id = str(uuid.UUID(admin_match[1]))
        else:
            admin_id = users["admin"]
            # The CLI has no stdin password option. Never print its argv.
            command(gvmd_cli + ["--user=admin", "--new-password=" + password], timeout=100)
        command(gvmd_cli + ["--modify-setting", "78eceaec-3385-11ea-b237-28d24461215b", "--value", admin_id], timeout=100)
        version = gmp("<get_version/>")
        record("Administrator and Feed Import Owner initialized after schema bootstrap", createdAdministrator=created_admin)
        record("Manager accepts fresh credentials over private GMP socket", gmpVersion=version.findtext("version"))
        cid = command(compose + ["ps", "-q", "target"]).strip()
        target = json.loads(command(["docker", "inspect", cid]))[0]
        networks = target["NetworkSettings"]["Networks"]
        if len(networks) != 1:
            raise RuntimeError("Target is unexpectedly attached to more than one network")
        network_name, target_network = next(iter(networks.items()))
        target_ip = str(ipaddress.IPv4Address(target_network["IPAddress"]))
        network = json.loads(command(["docker", "network", "inspect", network_name]))[0]
        if not network.get("Internal"):
            raise RuntimeError("Target network is not internal")
        protocol["target"] = {"container": cid, "address": target_ip, "port": 80, "network": network_name}
        record("Only the new disposable target address is selected", host=target_ip)

        def feed_diagnostics():
            for service in ("gvmd", "ospd-openvas", "pg-gvm"):
                logs = command(compose + ["logs", "--no-color", "--tail", "20", service], timeout=30, check=False)
                print("FEED DIAGNOSTICS " + service + "\n" + redact(logs)[-4000:], flush=True)

        stage("load official VT caches")
        def feeds_ready():
            feeds = gmp("<get_feeds/>")
            (output / "feed-status.xml").write_text(ET.tostring(feeds, encoding="unicode"))
            feed_info = []
            for feed in feeds.findall("feed"):
                if feed.find("currently_syncing") is not None:
                    raise RuntimeError("Feed import is still running: " + (feed.findtext("type") or "unknown"))
                feed_info.append({"type": feed.findtext("type"), "version": feed.findtext("version")})
            nvt_feeds = [item for item in feed_info if item["type"] in ("NVT", "NASL")]
            if len(nvt_feeds) != 1:
                raise RuntimeError("No unique NVT feed version is available")
            stamp = nvt_feeds[0]["version"] or ""
            if not re.fullmatch(r"\d{12,14}", stamp):
                raise RuntimeError("NVT feed version is not a recognized timestamp: " + stamp)
            feed_date = datetime.strptime(stamp[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - feed_date
            if not -timedelta(days=1) <= age <= timedelta(days=7):
                raise RuntimeError("NVT feed must be no older than 7 days and not from the future")
            nvt_response = gmp(f'<get_nvts nvt_oid="{TRACE_OID}" details="1"/>')
            nvt = nvt_response.find("nvt")
            if nvt is None:
                raise RuntimeError("Required official HTTP TRACE VT is not yet in the manager database")
            name = nvt.findtext("name") or ""
            if "TRACE" not in name.upper() or not nvt.findtext("family"):
                raise RuntimeError("Expected VT identity has changed: " + name)
            logs = command(compose + ["logs", "--no-color", "ospd-openvas", "gvmd"], timeout=60)
            if "Finished loading VTs" not in logs or not re.search(r"Updating VTs in database.*done", logs):
                raise RuntimeError("Scanner and manager have not both confirmed complete VT ingestion")
            protocol["feeds"] = feed_info
            return nvt

        nvt = wait_for("official feeds and scanner/manager VT caches", feeds_ready,
                       3600 if args.include_advisory_feeds else 1200, feed_diagnostics)
        family = nvt.findtext("family")
        record("Actual official HTTP TRACE VT and fresh feed loaded", oid=TRACE_OID, vtName=nvt.findtext("name"), family=family)
        # Upstream requires imported VTs and a Feed Import Owner before scan
        # configurations can be loaded. Rebuild only the official data objects
        # in this fresh manager, after both prerequisites are established.
        stage("import official scan configuration after VT caches")
        command(gvmd_cli + ["--rebuild-gvmd-data=all"], timeout=300)
        def configuration_ready():
            response = gmp(f'<get_configs config_id="{FULL_FAST_ID}"/>')
            if response.find("config") is None:
                raise RuntimeError("Official Full and fast configuration is not available after data import")
            return response
        wait_for("official scan configuration", configuration_ready, 180, feed_diagnostics)
        stage("create restricted scan configuration")
        scanners = gmp('<get_scanners details="1" filter="rows=-1"/>')
        candidates = [scanner for scanner in scanners.findall("scanner") if scanner.findtext("type") == "2"]
        if len(candidates) != 1:
            raise RuntimeError("Expected exactly one OpenVAS scanner in the new stack")
        scanner_id = candidates[0].get("id")
        gmp(element("verify_scanner", scanner_id=scanner_id))
        create = element("create_config")
        create.extend([element("name", "HCP safe HTTP TRACE acceptance"), element("copy", FULL_FAST_ID)])
        config_id = gmp(create).get("id")
        modify = element("modify_config", config_id=config_id)
        selection = element("family_selection")
        selection.append(element("growing", "0"))
        modify.append(selection)
        gmp(modify)
        # GMP deliberately preserves partial selections when a family is
        # omitted. Clear those explicitly before adding the single safe VT.
        cleared = gmp(element("get_configs", config_id=config_id, details="1"))
        for old_family in cleared.findall("./config/families/family"):
            if int(old_family.findtext("nvt_count") or "0"):
                clear = element("modify_config", config_id=config_id)
                old_selection = element("nvt_selection")
                old_selection.append(element("family", old_family.findtext("name")))
                clear.append(old_selection)
                gmp(clear)
        modify = element("modify_config", config_id=config_id)
        selection = element("nvt_selection")
        selection.append(element("family", family))
        selection.append(element("nvt", oid=TRACE_OID))
        modify.append(selection)
        for name, value in (("safe_checks", "yes"), ("auto_enable_dependencies", "yes"), ("optimize_test", "no")):
            preference = element("preference")
            preference.extend([element("name", name), element("value", base64.b64encode(value.encode()).decode())])
            modify.append(preference)
        gmp(modify)
        config_response = gmp(element("get_configs", config_id=config_id, details="1"))
        (output / "selected-config.xml").write_text(ET.tostring(config_response, encoding="unicode"))
        config = config_response.find("config")
        if config is None or config.findtext("nvt_count") != "1":
            raise RuntimeError("Restricted config must explicitly select exactly one official VT")
        selected = gmp(element("get_nvts", config_id=config_id))
        if {entry.get("oid") for entry in selected.findall("nvt")} != {TRACE_OID}:
            raise RuntimeError("Scanner selection contains unexpected VTs")
        preferences = {entry.findtext("name"): entry.findtext("value") for entry in config.findall("./preferences/preference")}
        if preferences.get("safe_checks") != "yes" or preferences.get("auto_enable_dependencies") != "yes":
            raise RuntimeError("Safe checks and automatic dependencies were not persisted")
        record("Restricted single-VT selection and safe scanner preferences verified")
        create = element("create_port_list")
        create.extend([element("name", "Only disposable HTTP port 80"), element("port_range", "T:80")])
        port_id = gmp(create).get("id")
        create = element("create_target")
        create.extend([element("name", "Owned disposable HTTP target"), element("hosts", target_ip),
                       element("port_list", id=port_id), element("alive_tests", "Consider Alive")])
        target_id = gmp(create).get("id")
        create = element("create_task")
        create.extend([element("name", "HCP live HTTP TRACE acceptance"), element("config", id=config_id),
                       element("target", id=target_id), element("scanner", id=scanner_id)])
        task_id = gmp(create).get("id")
        stage("run real network scan")
        start = gmp(element("start_task", task_id=task_id))
        report_id = start.findtext("report_id")
        if not report_id:
            raise RuntimeError("Manager did not return a real report ID")
        protocol.update(taskId=task_id, nativeReportId=report_id)
        save()

        def task_done():
            task = gmp(element("get_tasks", task_id=task_id, details="1")).find("task")
            status = task.findtext("status") if task is not None else "missing"
            if status == "Done":
                return task
            if status in ("Stopped", "Interrupted", "Internal Error", "Delete Requested"):
                raise ValueError("Scan terminated without success: " + status)
            raise RuntimeError("Scan status: " + str(status))

        wait_for("completed network scan", task_done, 1200)
        record("Actual scan reaches Done", reportId=report_id)
        stage("export native XML and verify HCP normalization")
        native = gmp(element("get_reports", report_id=report_id, details="1", ignore_pagination="1",
                             filter="first=1 rows=-1 levels=hmlgdf min_qod=0 apply_overrides=0"))
        native_path = output / "native-report.xml"
        native_path.write_text(ET.tostring(native, encoding="unicode"))
        reports = [entry for entry in native.iter("report") if entry.find("results") is not None]
        if len(reports) != 1 or reports[0].findtext("scan_run_status") != "Done":
            raise RuntimeError("Export is not one completed native report")
        report = reports[0]
        results = report.findall("./results/result")
        if any(result.findtext("host") != target_ip for result in results):
            raise RuntimeError("Native report includes an unexpected target")
        matches = [result for result in results if result.find("nvt") is not None and result.find("nvt").get("oid") == TRACE_OID]
        if not matches or not any(float(result.findtext("severity") or "0") > 0 for result in matches):
            raise RuntimeError("Official VT failed to detect the deliberately enabled HTTP TRACE method")
        if not report.findtext("scan_start") or not report.findtext("scan_end"):
            raise RuntimeError("Native report lacks actual scan timestamps")
        normalized_path = output / "hcp-report.json"
        command([sys.executable, str(REPO / "ansible/scripts/hcp-controller-scan.py"), "greenbone-report",
                 "--host", target_ip, "--inventory-host", "greenbone-owned-target", "--input", str(native_path),
                 "--run-id", project, "--output", str(normalized_path)], timeout=60)
        normalized = json.loads(normalized_path.read_text())
        scanner = normalized.get("scanner", {})
        if scanner.get("partial") is not False or scanner.get("imported") is not True:
            raise RuntimeError("HCP correctly rejected/marked the live export partial; investigate the actual report")
        if scanner.get("matchedResults") != len(results) or scanner.get("excludedOtherHostResults") != 0:
            raise RuntimeError("HCP result count or host binding differs from native report")
        if scanner.get("scanStartedAt") != report.findtext("scan_start") or scanner.get("scanEndedAt") != report.findtext("scan_end"):
            raise RuntimeError("HCP scan timestamps differ from the original scanner timestamps")
        for result in matches:
            nvt_result = result.find("nvt")
            markers = ["result=" + result.get("id", ""), "oid=" + TRACE_OID, "host=" + target_ip,
                       "port=" + (result.findtext("port") or "unknown"),
                       "severity=" + (result.findtext("severity") or "unknown"),
                       "qod=" + (result.findtext("qod/value") or "unknown")]
            markers += ["cve=" + nvt_result.findtext("cve")] if nvt_result.findtext("cve") else []
            finding = next((entry for entry in normalized.get("findings", [])
                            if all(marker in entry.get("evidence", "") for marker in markers)), None)
            if finding is None or finding.get("status") != "failed":
                raise RuntimeError("HCP lost expected TRACE evidence or failed finding status")
            for reference in nvt_result.findall("./refs/ref"):
                if reference.get("type", "").lower() == "cve" and reference.get("id", "") not in finding["evidence"]:
                    raise RuntimeError("HCP lost a native CVE reference")
        target_log = command(compose + ["logs", "--no-color", "target"])
        if '"TRACE ' not in target_log:
            raise RuntimeError("Target access log does not confirm an actual network TRACE request")
        record("Known HTTP TRACE finding preserved with host, OID, port, severity and QoD", resultCount=len(results),
               knownFindingCount=len(matches), nativeXmlSha256=hashlib.sha256(native_path.read_bytes()).hexdigest())
        protocol["status"] = "passed"
        stage("completed")
    except Exception as error:
        protocol["status"] = "failed"
        protocol["error"] = redact(f"{type(error).__name__}: {error}")
        print("FAIL " + protocol["error"], file=sys.stderr, flush=True)
    finally:
        protocol["finishedAt"] = datetime.now(timezone.utc).isoformat()
        if compose_file.exists():
            try:
                result = subprocess.run(compose + ["logs", "--no-color", "--tail", "1500"], cwd=REPO,
                                        capture_output=True, text=True, timeout=45)
                (output / "services.log").write_text(redact(result.stdout + result.stderr))
                if protocol["status"] != "passed":
                    print("FINAL SERVICE DIAGNOSTICS\n" + redact(result.stdout + result.stderr)[-8000:], flush=True)
                    for service in ("gvmd", "ospd-openvas"):
                        diagnostic = subprocess.run(compose + ["logs", "--no-color", "--tail", "100", service], cwd=REPO,
                                                    capture_output=True, text=True, timeout=30)
                        print("FINAL " + service + "\n" + redact(diagnostic.stdout + diagnostic.stderr)[-12000:], flush=True)
            except (OSError, subprocess.SubprocessError) as error:
                protocol["logCollectionError"] = redact(str(error))
            try:
                result = subprocess.run(compose + ["down", "-v", "--remove-orphans"], cwd=REPO,
                                        capture_output=True, text=True, timeout=120)
                protocol["cleanupSucceeded"] = result.returncode == 0
                if result.returncode:
                    protocol["cleanupError"] = redact(result.stderr[-2000:])
            except (OSError, subprocess.SubprocessError) as error:
                protocol["cleanupSucceeded"] = False
                protocol["cleanupError"] = redact(str(error))
            if protocol.get("cleanupSucceeded") is False and protocol["status"] == "passed":
                protocol["status"] = "failed"
                protocol["error"] = "Scanning assertions passed but disposable stack cleanup failed"
        save()
    return 0 if protocol["status"] == "passed" and protocol.get("cleanupSucceeded") else 1


if __name__ == "__main__":
    raise SystemExit(main())
