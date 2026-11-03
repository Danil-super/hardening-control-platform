# Final Debian CVE evidence — project JSON and PDF

This is the next integrated stage of [Issue #12](https://github.com/Danil-super/hardening-control-platform/issues/12). It builds on the pinned full-source snapshot and read-only per-finding preview. It does **not** authorize package updates, attest the Debian publisher, or prove universal CVE coverage.

## Exact unnormalized sources

The final project report enumerates the original saved `vulnerabilities` reports for the host and reads each original raw finding, not the deduplicated correlation list. Each finding with a `debianTrackerPreview` is projected into a separate `debianTrackerEvidence` tuple containing:

- Original source-report ID and SHA-256, original finding ID and scanner status/applicability;
- CVE, binary package and installed version, source package and installed source version, exact Debian release;
- Preliminary candidate status/verdict/reason, fixed version and disagreement with Trivy;
- Full immutable Debian tracker feed SHA-256, derived CVE excerpt SHA-256, capture time and pin mode;
- Explicit unverified-publisher flags and no-remediation authorization.

A separate `debianTrackerEvidenceSha256` digest covers the canonicalized complete projection with its host alias. It is saved in the immutable final JSON and printed in the final PDF. A separate `assertDebianTrackerEvidenceMultiset` checks exact source→projection tuple multiplicities, including repeated CVE package/version observations with different finding IDs. Duplicate original finding IDs, loss/substitution, invalid digest, unsupported distro/release, malformed trust fields or more than 4096 observations stop the export instead of silently truncating it. Native Debian version ordering was evaluated at the original CVE scan stage, not re-run to misrepresent current host state.

The PDF renderer prints **all** saved Debian tuples, source/finding IDs, observed versions, fixed thresholds, both snapshot hashes, source JSON hash and projection digest. It rejects contradicted authority flags, malformed digests and duplicate finding keys. Large PDFs still have the global 12 MiB bound, which fails creation rather than dropping rows.

## Regression verification

- `web/tests/debian-tracker-export.test.mjs`: preserves the exact multiset, verifies no trust escalation, rejects corrupted/duplicated/over-budget evidence.
- `web/tests/project-report.test.mjs`: writes a real project final snapshot and parses actual compressed PDF streams to confirm every original Debian CVE and both layers of hash provenance remain visible.
- `ansible/tests/test_final_report_pdf.py`: rejects false publisher claims, duplicate finding IDs, invalid digests and forbidden remediation assertions at the PDF layer.

## Explicit remaining requirements

Actual host/package provenance from signed repository metadata, independent Debian publisher authentication, freshness of the **publisher** rather than just local capture time, and a full native Debian VM exercise of the exact final-project-export path remain unverified. The imported public tracker JSON schema is unstable. Findings that disagree with Trivy remain conflicting evidence for human review and are never automatically suppressed. No automatic package remediation is granted by a candidate comparison.
