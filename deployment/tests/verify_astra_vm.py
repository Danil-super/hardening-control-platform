#!/usr/bin/env python3
"""Boot an official Astra VM and exercise unchanged production scanner paths.

Only the owned guest is changed. Images, private keys, seed and writable disks
stay outside artifacts. This is an acceptance of two base amd64 images, not a
claim about all releases, mandatory controls, or overall CVE recall.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from verify_astra_scap import raw_results

ROOT = Path(__file__).resolve().parents[2]
HOST = "hcp-real-astra"
PROFILE = "xccdf_org.hcp_profile_astra_baseline"
RULE = "xccdf_org.hcp_rule_passwd_permissions"
SOURCES = ROOT / "deployment/astra-vm/sources.json"
NS = {"o": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


def run(argv, output=None, timeout=120, accepted=(0,), env=None):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, env=env)
    if output:
        output.write_text(result.stdout)
    if result.returncode not in accepted:
        raise RuntimeError("Command failed (exit %s): %r\n%s" %
                           (result.returncode, argv, result.stdout[-14000:]))
    return result


def download(source, target, opener=urllib.request.urlopen):
    """Bound bytes and time and verify pinned publisher metadata before use."""
    assert source["url"].startswith("https://")
    start, count, digest = time.monotonic(), 0, hashlib.sha256()
    temporary = target.with_suffix(target.suffix + ".download")
    try:
        with opener(source["url"], timeout=60) as response, temporary.open("xb") as stream:
            assert urllib.parse.urlsplit(response.geturl()).scheme == "https"
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > source["bytes"] or time.monotonic() - start > 600:
                    raise ValueError("Download exceeded pinned byte/time limit")
                digest.update(chunk)
                stream.write(chunk)
        if count != source["bytes"] or digest.hexdigest() != source["sha256"]:
            raise ValueError("Publisher SHA-256 or byte count mismatch")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def verify_vendor_control(path, source):
    """Check the labelled expectation against actual pinned vendor predicates."""
    tree = ET.parse(path)
    definitions = tree.findall("o:definitions/o:definition", NS)
    assert len(definitions) == source["definitionCount"]
    selected = [entry for entry in definitions if entry.get("id") == source["definitionId"]]
    assert len(selected) == 1 and selected[0].get("class") == "vulnerability"
    assert any(entry.get("ref_id") == source["cve"] for entry in selected[0].iter()
               if entry.tag.endswith("}reference"))
    criteria = selected[0].find("o:criteria", NS)
    assert criteria.get("operator") == "OR"
    nodes = {entry.get("id"): entry for entry in tree.getroot().iter() if entry.get("id")}
    packages = []
    for criterion in criteria:
        assert criterion.tag.endswith("}criterion") and criterion.get("negate", "false") == "false"
        test = nodes[criterion.get("test_ref")]
        assert test.tag.endswith("}dpkginfo_test")
        obj = nodes[next(entry.get("object_ref") for entry in test if entry.tag.endswith("}object"))]
        state = nodes[next(entry.get("state_ref") for entry in test if entry.tag.endswith("}state"))]
        name = next(entry for entry in obj if entry.tag.endswith("}name"))
        evr = next(entry for entry in state if entry.tag.endswith("}evr"))
        assert name.get("operation", "equals") == "equals"
        assert evr.get("datatype") == "debian_evr_string" and evr.get("operation") == "less than"
        assert evr.text == source["fixedVersion"]
        packages.append(name.text)
    assert sorted(packages) == sorted(source["packages"])


def verify_oval_report(report, source, release, expected):
    scanner = report["scanner"]
    assert scanner["evaluationPerformed"] is True, scanner.get("partialReasons")
    assert scanner["hostIdentity"]["id"] == "astra"
    assert scanner["hostIdentity"]["astraVersion"].startswith(release)
    assert scanner["database"]["sha256"] == source["sha256"]
    assert scanner["database"]["checksumVerified"] is True
    assert scanner["definitionCount"] == source["definitionCount"]
    selected = [entry for entry in scanner["definitionResults"] if entry["id"] == source["definitionId"]]
    assert len(selected) == 1 and selected[0]["result"] == expected, selected
    assert source["cve"] in selected[0]["cveIds"]
    findings = [entry for entry in report["findings"] if entry["id"] == source["definitionId"]]
    assert len(findings) == (1 if expected == "true" else 0)
    if findings:
        assert findings[0]["status"] == "failed" and source["cve"] in findings[0]["vulnerability"]["cveIds"]
    assert report["summary"]["score"] is None
    return {"definitionId": source["definitionId"], "cve": source["cve"],
            "result": selected[0]["result"], "definitionCount": scanner["definitionCount"],
            "partial": scanner["partial"], "partialReasons": scanner["partialReasons"],
            "resultSha256": scanner["resultSha256"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", choices=("1.8.1", "1.8.6"), required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Disposable GitHub-hosted runner required"
    work = args.work_dir.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    assert work != runner_temp and work.is_relative_to(runner_temp) and not work.exists()
    work.mkdir(mode=0o700)
    artifacts = work / "artifacts"
    reports = artifacts / "reports"
    reports.mkdir(parents=True)
    sources = json.loads(SOURCES.read_text())
    image, oval = sources["images"][args.release], sources["oval"]
    protocol = {"status": "running", "release": args.release, "image": image, "oval": oval,
                "realAstraHostVerified": False, "syntheticIdentity": False,
                "limitations": ["Two base amd64 images only; no claim about max/mandatory controls or other releases", "One vendor CVE control does not estimate all-scanner recall/precision", "Official full OVAL evaluated; unknown definitions retain partial status"], "checks": []}

    def checkpoint(name, detail):
        protocol["checks"].append({"name": name, "detail": detail})
        write_json(artifacts / "protocol.json", protocol)
        print("PASS: " + name, flush=True)

    write_json(artifacts / "protocol.json", protocol)
    download(image, work / "source.qcow2")
    info = json.loads(run(["qemu-img", "info", "--output=json", str(work / "source.qcow2")]).stdout)
    assert info["format"] == "qcow2" and not info.get("backing-filename") and info["virtual-size"] <= 50 * 1024**3
    download(oval, work / "vendor.xml")
    verify_vendor_control(work / "vendor.xml", oval)
    checkpoint("Publisher images and full OVAL verified by SHA-256", {"imageBytes": image["bytes"], "ovalBytes": oval["bytes"]})
    for name in ("client", "server"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)])
    config = {"hostname": HOST, "ssh_pwauth": False, "disable_root": True,
              "users": ["default", {"name": "hcp-ci", "groups": ["astra-admin"], "sudo": "ALL=(ALL) NOPASSWD:ALL", "lock_passwd": True,
                                     "parsec_user_max_ilev": "high", "ssh_authorized_keys": [(work / "client.pub").read_text().strip()]}],
              "ssh_keys": {"ed25519_private": (work / "server").read_text(), "ed25519_public": (work / "server.pub").read_text()},
              "growpart": {"mode": "auto", "devices": ["/"]}, "resize_rootfs": True}
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (work / "user-data").chmod(0o600)
    write_json(work / "meta-data", {"instance-id": "hcp-astra-" + args.release, "local-hostname": HOST})
    run(["cloud-localds", str(work / "seed.iso"), str(work / "user-data"), str(work / "meta-data")])
    (work / "seed.iso").chmod(0o600)
    run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(work / "source.qcow2"), str(work / "guest.qcow2")])
    run(["qemu-img", "resize", str(work / "guest.qcow2"), "12G"])
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    public = " ".join((work / "server.pub").read_text().split()[:2])
    (work / "known_hosts").write_text("[127.0.0.1]:%s %s\n" % (port, public))
    ssh_options = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=8", "-o", "UserKnownHostsFile=" + str(work / "known_hosts")]
    ssh = ["ssh", "-i", str(work / "client"), "-p", str(port)] + ssh_options + ["hcp-ci@127.0.0.1"]

    def remote(command, **kwargs):
        return run(ssh + [command], **kwargs)

    acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    protocol["acceleration"] = acceleration
    qemu_args = ["qemu-system-x86_64", "-machine", "q35,accel=" + acceleration, "-m", "4096", "-smp", "2", "-display", "none", "-monitor", "none", "-serial", "file:" + str(artifacts / "guest-console.log"), "-no-reboot",
                 "-drive", "file=" + str(work / "guest.qcow2") + ",if=virtio,format=qcow2", "-drive", "file=" + str(work / "seed.iso") + ",if=virtio,format=raw,readonly=on",
                 "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22", "-device", "virtio-net-pci,netdev=net0"]
    if acceleration == "kvm":
        qemu_args.extend(["-cpu", "host"])
    def terminated(_signum, _frame):
        raise InterruptedError("CI cancellation")
    signal.signal(signal.SIGTERM, terminated)
    with (artifacts / "qemu.log").open("w") as log:
        process = subprocess.Popen(qemu_args, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + (420 if acceleration == "kvm" else 900)
            while time.monotonic() < deadline:
                assert process.poll() is None, "Guest exited; inspect console and qemu logs"
                if remote("true", accepted=(0, 255), timeout=12).returncode == 0:
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Guest SSH readiness timeout; inspect console")
            remote("sudo cloud-init status --wait", output=artifacts / "cloud-init-status.txt", timeout=300)
            identity = remote("cat /etc/os-release; printf '\\nRELEASE='; cat /etc/astra_version; printf '\\nKERNEL='; uname -r; printf 'MACHINE_ID='; cat /etc/machine-id").stdout
            (artifacts / "guest-identity.txt").write_text(identity)
            assert 'ID=astra\n' in identity or 'ID="astra"\n' in identity
            assert "RELEASE=" + args.release in identity and "MACHINE_ID=" in identity
            assert "KERNEL=" + os.uname().release not in identity
            protocol["realAstraHostVerified"] = True
            checkpoint("Genuine guest identity and independent Astra kernel", identity)
            package_query = "dpkg-query -W -f='${binary:Package}\\t${Version}\\n' " + " ".join(map(shlex.quote, oval["packages"])) + " 2>/dev/null || true"
            original_packages = remote(package_query).stdout
            remote("if ! command -v oscap >/dev/null; then sudo apt-mark hold libssl3 openssl; sudo apt-get update -o Acquire::Retries=2; if apt-cache show openscap-scanner >/dev/null 2>&1; then sudo apt-get install -y --no-install-recommends openscap-scanner; else sudo apt-get install -y --no-install-recommends libopenscap8; fi; fi", output=artifacts / "guest-oscap-install.log", timeout=600)
            assert remote(package_query).stdout == original_packages, "Provisioning changed the CVE controls"
            remote("oscap --version", output=artifacts / "guest-oscap-version.txt")
            versions = dict(line.split("\t", 1) for line in original_packages.splitlines() if "\t" in line)
            assert versions, "No labelled package was installed in the actual image"
            matches = {name: remote("dpkg --compare-versions " + shlex.quote(version) + " lt " + shlex.quote(oval["fixedVersion"]), accepted=(0, 1)).returncode == 0 for name, version in versions.items()}
            assert any(matches.values()) == (image["expectedControl"] == "true"), {"versions": versions, "matches": matches}
            checkpoint("Independent installed-package version control", {"versions": versions, "vulnerablePredicates": matches})
            inventory = {"linux_hosts": {"hosts": {HOST: {"ansible_host": "127.0.0.1", "ansible_port": port, "ansible_user": "hcp-ci", "ansible_become": True, "ansible_python_interpreter": "/usr/bin/python3", "ansible_ssh_private_key_file": str(work / "client"), "ansible_ssh_common_args": shlex.join(ssh_options)}}}}
            write_json(work / "inventory.json", inventory)

            def playbook(name, phase, extra=None, timeout=600):
                variables = {"hcp_reports_dir": str(reports), "report_run_id": phase, **(extra or {})}
                file = work / ("vars-" + phase + ".json")
                write_json(file, variables)
                run(["ansible-playbook", "-i", str(work / "inventory.json"), str(ROOT / "ansible/playbooks" / (name + ".yml")), "-e", "@" + str(file)], output=artifacts / (phase + ".log"), timeout=timeout)

            playbook("collect-facts", "facts")
            playbook("package-inventory", "packages")
            packages = json.loads((reports / (HOST + "-packages-packages.json")).read_text())
            assert packages["packages"] and "astra" in packages["os"].lower()
            checkpoint("Production SSH facts and package collection", {"packages": len(packages["packages"]), "os": packages["os"]})
            original_mode = remote("stat -c '%a' /etc/passwd").stdout.strip()
            states = []
            try:
                for phase in ("baseline", "violation", "restored"):
                    if phase == "violation":
                        remote("sudo chmod o+x /etc/passwd")
                    if phase == "restored":
                        remote("sudo chmod " + shlex.quote(original_mode) + " /etc/passwd")
                    playbook("openscap-audit", phase, {"hcp_openscap_datastream": "/__hcp_builtin__/astra-baseline.xml", "hcp_openscap_profile": PROFILE, "hcp_openscap_policy_group": "ci-real-astra", "hcp_openscap_keep_arf": True})
                    raw = reports / ("." + HOST + "-openscap-" + phase + ".xml")
                    results, _evidence = raw_results(raw)
                    raw.rename(artifacts / (phase + ".arf.xml"))
                    normalized = json.loads((reports / (HOST + "-openscap-" + phase + ".json")).read_text())
                    selected = [entry for entry in normalized["findings"] if entry["id"] == "openscap_" + RULE]
                    assert len(selected) == 1 and selected[0]["status"] == ("failed" if phase == "violation" else "passed")
                    assert not {"error", "notchecked", "notselected"} & set(results.values()), results
                    states.append(results[RULE])
            finally:
                remote("sudo chmod " + shlex.quote(original_mode) + " /etc/passwd")
            assert states == ["pass", "fail", "pass"]
            checkpoint("Unmodified Astra baseline: native pass/fail/restored", states)
            config = {"mode": "online", "url": oval["url"], "sha256": oval["sha256"], "releasePattern": "1.8.*", "architectures": ["amd64"], "maxAgeDays": 90, "sourceName": "Official Astra 1.8 amd64 OVAL", "sourceReference": oval["metadataUrl"], "sourceReviewedAt": sources["reviewedAt"]}
            playbook("astra-oval-audit", "vendor-cve", {"hcp_oval_config": config}, timeout=1800)
            report_id = HOST + "-astra-oval-vendor-cve"
            report = json.loads((reports / (report_id + ".json")).read_text())
            detail = verify_oval_report(report, oval, args.release, image["expectedControl"])
            checkpoint("Full vendor OVAL and labelled native CVE result", detail)
            run(["node", str(ROOT / "deployment/tests/verify_astra_vm_normalization.mjs"), report_id, oval["definitionId"], oval["cve"], image["expectedControl"], str(artifacts / "web-normalized-oval.json")], output=artifacts / "web-normalization.log", env={**os.environ, "HCP_REPORTS_DIR": str(reports), "HCP_STATE_DIR": str(work / "state")})
            checkpoint("Production web normalization preserves native CVE evidence", True)
            protocol["status"] = "passed"
            write_json(artifacts / "protocol.json", protocol)
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
