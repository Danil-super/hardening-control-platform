#!/usr/bin/env python3
"""Real complete Astra SE 1.7 vendor OVAL source-vs-result native acceptance.

Executed only after the owned disposable Astra Linux guest has passed the
genuine 18-rule OpenSCAP experiment and SSH restoration gate. Full source
scope does NOT mean universal CVE recall or publisher authentication.
No original OVAL XML, scanner raw JSON, machine ID or private logs are uploaded.
"""
from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET

from download_astra17_ova import NoRedirect
from verify_astra_vm import download, verified_pinned_file
from verify_astra17_ova_audit import HOST, demand, file_sha256, load_private_json

VENDOR = {
    "url": "https://dl.astralinux.ru/artifactory/al-oval/1.7_x86-64/oval-definitions-alse-1.7.xml",
    "metadataUrl": "https://dl.astralinux.ru/artifactory/api/storage/al-oval/1.7_x86-64/oval-definitions-alse-1.7.xml",
    "bytes": 134668815,
    "sha256": "c9364c80d664907dc472475d2ef57689c314abecede7a58e7e9dae8250891d17",
}
NS_DEFINITION = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition"
ID = re.compile(r"^oval:[A-Za-z0-9_.:-]{3,200}$")
SOURCE_SCAN_ID_MAX = 1000000
VALID_STATES = frozenset({
    "true", "false", "unknown", "error", "not evaluated", "not applicable",
})


def exact_original_source_ids(path):
    """Stream XML and retain only bounded verified definition IDs."""
    ids = set()
    for _, element in ET.iterparse(str(path), events=("end",)):
        if element.tag == NS_DEFINITION:
            name = element.get("id")
            demand(type(name) is str and ID.fullmatch(name)
                   and name not in ids, "oval_source_id_invalid_or_duplicate")
            ids.add(name)
            demand(len(ids) <= SOURCE_SCAN_ID_MAX, "oval_source_too_many_definitions")
        element.clear()
    demand(bool(ids), "oval_source_has_no_definitions")
    return ids


def validate_original_native_oval(report, source_ids):
    """Compare the EXACT XML definition set against the real scanner result."""
    demand(type(report) is dict and report.get("inventoryHost") == HOST
           and report.get("mode") == "astra-oval",
           "native_oval_report_scope_invalid")
    scanner = report.get("scanner")
    demand(type(scanner) is dict, "native_oval_scanner_metadata_missing")
    identity = scanner.get("hostIdentity")
    demand(type(identity) is dict and identity.get("id") == "astra"
           and identity.get("astraVersion") == "1.7.6",
           "native_oval_wrong_observed_guest")
    source = scanner.get("database")
    demand(type(source) is dict and source.get("sha256") == VENDOR["sha256"]
           and source.get("checksumVerified") is True,
           "native_oval_source_sha_missing_or_mismatch")
    demand(scanner.get("available") is True
           and scanner.get("evaluationPerformed") is True
           and type(scanner.get("exitCode")) is int
           and scanner["exitCode"] in (0, 2),
           "native_oval_scanner_not_completed")
    demand(scanner.get("partial") is False
           and report.get("partial") is not True,
           "native_oval_partial_or_unavailable")
    reasons = scanner.get("partialReasons")
    demand(reasons is None or reasons == [],
           "native_oval_unresolved_partial_reasons")
    expected = len(source_ids)
    demand(type(scanner.get("definitionCount")) is int
           and scanner["definitionCount"] == expected,
           "oval_source_definition_count_mismatch")
    demand(type(scanner.get("evaluatedDefinitionCount")) is int
           and scanner["evaluatedDefinitionCount"] == expected,
           "oval_evaluated_definition_count_mismatch")
    listed = scanner.get("definitionResults")
    demand(type(listed) is list and len(listed) == expected,
           "native_oval_definition_results_incomplete")
    matched, results = set(), Counter()
    for item in listed:
        demand(type(item) is dict, "native_oval_definition_result_invalid")
        name, value = item.get("id"), item.get("result")
        demand(type(name) is str and name in source_ids and name not in matched,
               "native_oval_unknown_or_duplicate_definition")
        demand(type(value) is str and value in VALID_STATES,
               "native_oval_unrecognized_result")
        matched.add(name)
        results[value] += 1
    demand(matched == source_ids, "native_oval_source_result_set_differs")
    raw_sha = scanner.get("resultSha256")
    demand(type(raw_sha) is str and re.fullmatch(r"[a-f0-9]{64}", raw_sha),
           "native_oval_raw_results_sha_missing")
    demand(report.get("summary", {}).get("score") is None,
           "native_oval_fabricated_security_score")
    return {
        "definitionCountFromExactVendorXml": expected,
        "evaluatedDefinitions": expected,
        "observedResultStates": dict(sorted(results.items())),
        "sourceSha256": VENDOR["sha256"],
        "rawOvalsResultsSha256": raw_sha,
        "fullSelectedSourceEvaluated": True,
        "independentPublisherSignatureVerified": False,
        "generalAllCveRecallVerified": False,
        "reportCannotProveNoVulnerabilities": True,
    }


def evaluate_native_vendor_oval(work, reports, protocol, run_playbook):
    """Use the SAME real guest and same private inventory as completed HCP."""
    protocol["nativeHcp"]["stage"] = "vendor_oval_source_bytes"
    print("NATIVE HCP STAGE: verify exact Astra 1.7 vendor OVAL source", flush=True)
    original = work / "private-original-astra17-oval.xml"
    download(VENDOR, original,
             opener=urllib.request.build_opener(NoRedirect()).open,
             max_seconds=2400)
    demand(verified_pinned_file(original, VENDOR), "oval_original_source_digest_invalid")
    ids = exact_original_source_ids(original)
    protocol["nativeHcp"]["vendorOvalDefinitionsInSource"] = len(ids)

    policy = {
        "mode": "online", "url": VENDOR["url"],
        "sha256": VENDOR["sha256"], "releasePattern": "1.7.*",
        "architectures": ["amd64"], "maxAgeDays": 90,
        "sourceName": "Official Astra 1.7 OVAL exact snapshot",
        "sourceReference": VENDOR["metadataUrl"],
        "sourceReviewedAt": "2026-11-04",
    }
    protocol["nativeHcp"]["stage"] = "native_real_oval_evaluation"
    print("NATIVE HCP STAGE: run real native OVAL source via HCP playbook", flush=True)
    run_playbook(work, reports, "astra-oval-audit", "vendor-oval",
                 {"hcp_oval_config": policy}, protocol, timeout_seconds=2700)
    original_report = reports / (HOST + "-astra-oval-vendor-oval.json")
    parsed = load_private_json(original_report, limit=256 * 1024 * 1024)
    proof = validate_original_native_oval(parsed, ids)
    protocol["nativeHcp"]["sourceBoundVendorOval"] = {
        **proof, "normalizedOriginalJsonSha256": file_sha256(original_report),
        "originalXmlBytes": VENDOR["bytes"],
        "manufacturerSignatureNotIndependentlyVerified": True,
    }
    protocol["nativeHcp"]["fullOvalEvaluated"] = True
    protocol["nativeHcp"]["stage"] = "all_scoped_native_hcp_checks_complete"
    print("NATIVE HCP STAGE: exact Astra 1.7 OVAL source scope verified", flush=True)
