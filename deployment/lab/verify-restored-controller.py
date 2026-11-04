#!/usr/bin/env python3
"""Actual Docker restore drill using ONLY the disposable hcp-lab fixture.

CI stops the original HCP lab controller, snapshots its persistent runtime,
restores it into a distinct volume, verifies preserved bytes and HMAC, revokes
restored admin tokens, boots a second controller and tests real HTTP and SSH.
This is NOT an operator's production recovery drill or Astra acceptance.
Never publish the original runtime tar, SQLite, keys, cookie or lab .env.
"""
import hashlib
import http.cookiejar as cookiejar
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / ".lab/restore-verification.json"
HOST = "127.0.0.1"
SOURCE_URL = "http://127.0.0.1:3001"
RESTORED_URL = "http://127.0.0.1:3002"
LAB_PASSWORD = "lab-only-password"
CONFIRM = "INVALIDATE_ONLY_ISOLATED_RESTORED_HCP_SESSIONS"
SHA = "sha256:"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(argv, *, stdin=None, stdout=None, timeout=180):
    finished = subprocess.run(argv, stdin=stdin, stdout=stdout or subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, check=False)
    if finished.returncode:
        # Docker and tool stderr may contain sensitive paths or credentials.
        raise AssertionError("Isolated restore operation failed (nonzero exit) [" +
                             str(argv[1] if len(argv) > 1 else "command") + "]")
    return finished.stdout.decode("utf-8", "strict") if stdout is None else ""


def docker(*args, timeout=180):
    return run(["docker", *args], timeout=timeout)


def read_json(value):
    parsed = json.loads(value)
    require(isinstance(parsed, dict), "Expected one JSON record")
    return parsed


def http(client, base, route, *, payload=None, method=None, expected=200, origin=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        base + route, data=data,
        method=method or ("POST" if data is not None else "GET"),
        headers={"Content-Type": "application/json",
                 "Origin": origin or base},
    )
    try:
        response = client.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read(10 * 1024 * 1024)
    require(response.status == expected,
            "Unexpected HTTP status from isolated restored controller")
    return read_json(body.decode("utf-8", "strict"))


def safe_host_summary(hosts):
    return sorted({
        item["alias"]: {
            "alias": item["alias"],
            "reportCount": item.get("reportCount", 0),
            "credentialId": item.get("credentialId"),
            "credentialReady": item.get("credentialReady"),
            "credentialFingerprint": item.get("credentialFingerprint"),
        }
        for item in hosts
    }.values(), key=lambda h: h["alias"])


def find_source_volume(container):
    mounts = json.loads(docker("inspect", "--format", "{{json .Mounts}}", container))
    runtime = [v for v in mounts if v["Destination"] == "/var/lib/hcp"]
    require(len(runtime) == 1 and runtime[0].get("Type") == "volume"
            and runtime[0].get("Name", "").startswith("hcp-lab_"),
            "Expected unique lab-owned named volume")
    return runtime[0]["Name"]


def find_network(container):
    networks = json.loads(docker("inspect", "--format",
                                 "{{json .NetworkSettings.Networks}}", container))
    names = [key for key in networks if key.startswith("hcp-lab_")]
    require(len(names) == 1, "Expected exactly one isolated Docker lab network")
    return names[0]


def full_image(container):
    value = docker("inspect", "--format", "{{.Image}}", container).strip()
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None,
            "Lab controller must have an immutable image identity")
    return value


# Executed as Python inside a disposable container with two read-only mounts.
# Compare file contents and reject links in critical evidence trees. Never print
# original paths, host identities, SSH private keys or file contents.
COMPARE_CODE = r'''
from pathlib import Path
import hashlib, json, os, stat
source, target = Path("/before"), Path("/after")
critical = {"hcp.sqlite", "inventory.ini", "known_hosts"}
prefixes = ("reports/", "ssh-host-keys/", "sbom/")
count, bytes_count, reports, keys = 0, 0, 0, 0
for path in source.rglob("*"):
    rel = path.relative_to(source).as_posix()
    if rel not in critical and not rel.startswith(prefixes):
        continue
    if path.is_symlink():
        raise RuntimeError("critical backup path is symlinked")
    if not path.is_file():
        if path.is_dir():
            continue
        raise RuntimeError("unsupported evidence member")
    other = target / rel
    for parent in other.parents:
        if parent == target:
            break
        if parent.is_symlink():
            raise RuntimeError("restored critical subtree is symlinked")
    if other.is_symlink() or not other.is_file():
        raise RuntimeError("missing or linked restored evidence")
    if rel.startswith("ssh-host-keys/") and not rel.endswith(".pub"):
        if other.stat().st_mode & 0o077:
            raise RuntimeError("restored SSH key permissions invalid")
    def digest(p):
        h = hashlib.sha256()
        with p.open("rb") as inp:
            for chunk in iter(lambda: inp.read(1048576), b""):
                h.update(chunk)
        return h.hexdigest()
    if path.stat().st_size != other.stat().st_size or digest(path) != digest(other):
        raise RuntimeError("restored source bytes mismatch")
    count += 1
    bytes_count += path.stat().st_size
    reports += int(rel.startswith("reports/"))
    keys += int(rel.startswith("ssh-host-keys/"))
if count < 4 or reports == 0 or keys == 0:
    raise RuntimeError("restore lacks real reports or enrolled host keys")
print(json.dumps({"criticalFiles": count, "criticalBytes": bytes_count,
                  "reports": reports, "hostKeyFiles": keys}))
'''


def container_python(image, volume, scripts, args, config=None, receipt=None):
    command = ["docker", "run", "--rm", "--network", "none",
               "--volume", volume + ":/var/lib/hcp",
               "--volume", str(scripts) + ":/tools:ro"]
    if config:
        command += ["--volume", str(config) + ":/verification:ro"]
    if receipt:
        command += ["--volume", str(receipt) + ":/receipt"]
    command += ["--entrypoint", "python3", image, *args]
    return read_json(run(command, timeout=120))


def tar_restore_command(image, volume):
    # Docker does NOT connect the container's stdin unless -i is specified.
    # This is a required property when extracting the original private tar
    # stream from a local file into the isolated restored named volume.
    return ["docker", "run", "--rm", "-i", "--network", "none",
            "-v", volume + ":/to", "--entrypoint", "tar",
            image, "-C", "/to", "-xzf", "-"]


def offline_checkpoint(image, volume):
    # On the already-copied disposable volume ONLY: commit valid WAL frames
    # using SQLite itself, and refuse a lingering WAL instead of deleting it.
    script = ("""import sqlite3, os; p='/var/lib/hcp/hcp.sqlite'; """
              """c=sqlite3.connect(p); c.execute('PRAGMA wal_checkpoint(TRUNCATE)'); """
              """c.close(); assert not os.path.exists(p+'-wal') and not os.path.exists(p+'-shm')""")
    run(["docker", "run", "--rm", "--network", "none",
         "--volume", volume + ":/var/lib/hcp",
         "--entrypoint", "python3", image, "-c", script], timeout=120)


def wait_for_health(base, seconds=150):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base + "/login", timeout=4) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise AssertionError("Restored controller did not become healthy")


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "Only disposable GitHub-hosted CI may run this automatic lab drill")
    require(Path.cwd().resolve() == ROOT, "Run from the repository root")
    require(not PROTOCOL.exists(), "Do not replace historical restore protocol")
    original = docker("compose", "-f", "deployment/lab/docker-compose.yml",
                      "ps", "-q", "hcp").strip()
    require(len(original) >= 12, "Original lab HCP is not running")
    # Refuse to stop anything other than the exact disposable fixture:
    # Docker commands run only on GitHub-hosted CI, never user installations.
    original_info = json.loads(docker("inspect", "--format", "{{json .Config.Env}}", original))
    lab_env = dict(item.split("=", 1) for item in original_info if "=" in item)
    require(all(lab_env.get(k) == v for k, v in {
        "HCP_ADMIN_PASSWORD": "lab-only-password",
        "HCP_AUTH_SECRET": "lab-only-secret-change-in-production",
        "HCP_AUDIT_HMAC_KEY": "lab-only-audit-integrity-key-change-in-production",
    }.items()), "Refusing to operate on non-fixture HCP controller")
    require(docker("inspect", "--format", "{{.State.Running}}", original).strip() == "true",
            "Lab controller must be running before stopping it")
    image = full_image(original)
    source = find_source_volume(original)
    network = find_network(original)
    old_jar = cookiejar.CookieJar()
    old = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(old_jar))
    http(old, SOURCE_URL, "/api/ansible/auth/login", payload={"password": LAB_PASSWORD})
    old_hosts = http(old, SOURCE_URL, "/api/ansible/hosts")
    old_events = http(old, SOURCE_URL, "/api/ansible/incidents")
    require(old_hosts.get("ok") is True and old_events.get("integrity", {}).get("valid") is True
            and old_events["integrity"]["entries"] > 0,
            "Original lab state lacks source-bound host evidence or HMAC integrity")
    before_hosts = safe_host_summary(old_hosts["hosts"])
    require(any(x.get("credentialReady") for x in before_hosts)
            and any(x.get("reportCount", 0) > 0 for x in before_hosts),
            "Expected real enrolled keys and reports before backup")
    state = {
        "schemaVersion": 1, "scope": "disposable-Debian-SSH-HCP-controller-restore",
        "realProductionRecoveryVerified": False,
        "astraNativeRecoveryVerified": False,
        "oldSessionRejected": False,
        "newLoginVerified": False,
        "recoveredHostKeysVerified": False,
        "restoredAuditChainVerified": False,
        "restoredSshPingVerified": False,
        "recoveredReportsVerified": False,
    }
    cleanup_id = uuid4().hex[:12]
    restored_name = "hcp-ci-restored-" + cleanup_id
    restored_volume = "hcp-ci-restored-volume-" + cleanup_id
    os.makedirs(ROOT / ".lab", exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="restore-private-", dir=ROOT / ".lab"))
    staging.chmod(0o700)
    stopped = False
    new_container = False
    new_volume = False
    begin = time.monotonic()
    try:
        config_dir = staging / "verification"
        config_dir.mkdir(mode=0o700)
        env = config_dir / ".env"
        env.write_text("HCP_AUDIT_HMAC_KEY=lab-only-audit-integrity-key-change-in-production\n",
                       encoding="utf-8")
        env.chmod(0o600)
        docker("stop", "--time", "60", original, timeout=90)
        stopped = True
        runtime_archive = staging / "runtime.tar.gz"
        with runtime_archive.open("xb") as output:
            os.chmod(runtime_archive, 0o600)
            run(["docker", "run", "--rm", "--network", "none", "-v",
                 source + ":/from:ro", "--entrypoint", "tar",
                 image, "-C", "/from", "-czf", "-", "."], stdout=output, timeout=240)
        digest = hashlib.sha256()
        with runtime_archive.open("rb") as original_tar:
            for chunk in iter(lambda: original_tar.read(1048576), b""):
                digest.update(chunk)
        state["sourceTarSha256"] = digest.hexdigest()
        state["sourceTarBytes"] = runtime_archive.stat().st_size
        require(0 < state["sourceTarBytes"] < 10 * 1024**3,
                "Lab backup archive exceeds bounded acceptance budget")
        docker("volume", "create", restored_volume)
        new_volume = True
        with runtime_archive.open("rb") as input_file:
            run(tar_restore_command(image, restored_volume),
                stdin=input_file, timeout=240)
        comparison = read_json(docker("run", "--rm", "--network", "none",
            "-v", source + ":/before:ro", "-v", restored_volume + ":/after:ro",
            "--entrypoint", "python3", image, "-c", COMPARE_CODE, timeout=240))
        require(comparison["reports"] > 0 and comparison["hostKeyFiles"] > 0,
                "Restore discarded critical host evidence")
        state["comparedCriticalFiles"] = comparison["criticalFiles"]
        state["comparedCriticalBytes"] = comparison["criticalBytes"]
        state["recoveredReportsVerified"] = True
        state["recoveredHostKeysVerified"] = True
        # SQLite normalization is permitted only on the already restored copy.
        offline_checkpoint(image, restored_volume)
        scripts = ROOT / "deployment/tests"
        audit_before = container_python(image, restored_volume, scripts, [
            "/tools/verify_restored_audit_chain.py",
            "--restored-runtime", "/var/lib/hcp",
            "--env", "/verification/.env", "--acknowledge-stopped",
        ], config=config_dir)
        require(audit_before["entries"] == old_events["integrity"]["entries"]
                and audit_before["legacyEntries"] == old_events["integrity"]["legacyEntries"],
                "Restored audit chain differs from the original controller")
        preview = container_python(image, restored_volume, scripts, [
            "/tools/revoke_restored_admin_sessions.py",
            "--restored-runtime", "/var/lib/hcp",
        ])
        require(preview["status"] == "preview-only" and preview["storedSessionHashes"] >= 1,
                "Original browser token did not survive the pre-revocation snapshot")
        receipt_dir = staging / "receipts"
        receipt_dir.mkdir(mode=0o700)
        revoke = container_python(image, restored_volume, scripts, [
            "/tools/revoke_restored_admin_sessions.py",
            "--restored-runtime", "/var/lib/hcp",
            "--apply", "--confirm-isolated-stopped",
            "--confirm-text", CONFIRM,
            "--expected-db-sha256", preview["databaseSha256"],
            "--output", "/receipt/revoke.json",
        ], receipt=receipt_dir)
        require(revoke["revocationPerformed"] is True
                and revoke["remainingSessionHashes"] == 0,
                "Restored bearer token hashes remain active")
        audit_after = container_python(image, restored_volume, scripts, [
            "/tools/verify_restored_audit_chain.py",
            "--restored-runtime", "/var/lib/hcp",
            "--env", "/verification/.env", "--acknowledge-stopped",
        ], config=config_dir)
        require(audit_before["lastEntryHash"] == audit_after["lastEntryHash"]
                and audit_before["entries"] == audit_after["entries"],
                "Revoking restored sessions altered the immutable HMAC audit trail")
        state["restoredAuditChainVerified"] = True
        # Launch a second HCP with the SAME built image and independent
        # restored volume; only synthetic CI lab secrets are present.
        run(["docker", "run", "-d", "--name", restored_name,
             "--network", network,
             "-p", "127.0.0.1:3002:3000",
             "-v", restored_volume + ":/var/lib/hcp",
             "-e", "HCP_ADMIN_PASSWORD=lab-only-password",
             "-e", "HCP_AUTH_SECRET=lab-only-secret-change-in-production",
             "-e", "HCP_AUDIT_HMAC_KEY=lab-only-audit-integrity-key-change-in-production",
             "-e", "HCP_SCHEDULE_API_KEY=hcp-lab-scheduler-only-key-change-in-production",
             "-e", "HCP_KNOWN_HOSTS_PATH=/var/lib/hcp/known_hosts",
             "-e", "HCP_REPORTS_DIR=/var/lib/hcp/reports",
             "-e", "HCP_STATE_DIR=/var/lib/hcp",
             "-e", "HCP_TRIVY_MODE=offline",
             image], timeout=60)
        new_container = True
        wait_for_health(RESTORED_URL)
        anonymous = urllib.request.build_opener()
        require(http(anonymous, RESTORED_URL, "/api/ansible/session",
                     expected=401)["error"] == "auth_required",
                "Restored protected API accepted an unauthenticated request")
        # Old cookie was created against the source HCP on the same host and
        # deliberately carried to port 3002. It must now be rejected.
        require(http(old, RESTORED_URL, "/api/ansible/session",
                     expected=401)["error"] == "auth_required",
                "Original lab cookie remained valid after restored-session revocation")
        state["oldSessionRejected"] = True
        fresh = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()))
        http(fresh, RESTORED_URL, "/api/ansible/auth/login",
             payload={"password": LAB_PASSWORD})
        require(http(fresh, RESTORED_URL, "/api/ansible/session")["ok"] is True,
                "Restored admin could not create a fresh valid session")
        state["newLoginVerified"] = True
        require(http(fresh, RESTORED_URL, "/api/ansible/hosts",
                     method="POST", payload={}, origin="https://foreign.invalid",
                     expected=403)["error"] == "bad_origin",
                "Restored application failed same-origin mutation protection")
        restored_hosts = http(fresh, RESTORED_URL, "/api/ansible/hosts")
        require(safe_host_summary(restored_hosts["hosts"]) == before_hosts,
                "Restored host credentials or reports differ from original snapshot")
        events = http(fresh, RESTORED_URL, "/api/ansible/incidents")
        require(events["integrity"]["valid"] is True
                and events["integrity"]["entries"] == audit_before["entries"],
                "Restored HCP API cannot verify original immutable audit trail")
        # Connect to the real disposable SSH container with its restored
        # individual HCP-managed identity, not a synthetic protocol fixture.
        check = docker("exec", "-u", "node", restored_name, "ansible", "-i",
                       "/app/ansible/inventory.ini", "lab-insecure", "-m", "ping",
                       timeout=100)
        require("pong" in check, "Restored HCP cannot reach the authorized SSH target")
        state["restoredSshPingVerified"] = True
        state["originalAuditEntries"] = audit_before["entries"]
        state["restoredHostCount"] = len(before_hosts)
        state["storedSessionHashesRevoked"] = revoke["sessionsRemoved"]
        state["restoreElapsedSeconds"] = round(time.monotonic() - begin, 2)
        state["status"] = "passed-lab-controller-restore"
        state["limitations"] = [
            "Only disposable GitHub Debian SSH labs; not the operator's Ubuntu or Astra SE 1.7.",
            "Same-build Docker volume restoration; not complete production backup of image, secrets or external services.",
            "Verified selected source bytes, HMAC chain, old/new sessions, HTTP authorization and real lab SSH ping.",
            "Cannot attest independent origin of a locally stored HMAC key or production operational resilience.",
        ]
        PROTOCOL.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        PROTOCOL.chmod(0o600)
        print("PASS: disposable restored HCP boots with old cookies rejected, preserved evidence and real SSH.")
    except BaseException:
        # A failed laboratory recovery is never a PASS. Save a small, sanitized
        # checkpoint even when secret-bearing source archives are discarded.
        state["status"] = "failed-lab-controller-restore"
        state["restoreElapsedSeconds"] = round(time.monotonic() - begin, 2)
        state["limitations"] = ["No production recovery attested; inspect CI job steps."]
        PROTOCOL.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        PROTOCOL.chmod(0o600)
        raise
    finally:
        if new_container:
            subprocess.run(["docker", "rm", "-f", restored_name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=False)
        if new_volume:
            subprocess.run(["docker", "volume", "rm", restored_volume],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=False)
        if stopped:
            # Never leave the original CI fixture stopped after the restore
            # exercise, even when the new controller or HMAC validation fails.
            subprocess.run(["docker", "start", original], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60, check=False)
        # A root-owned receipt can exist; remove only this random local path.
        subprocess.run(["sudo", "chown", "-R", str(os.getuid()) + ":" + str(os.getgid()),
                        str(staging)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=20, check=False)
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    main()
