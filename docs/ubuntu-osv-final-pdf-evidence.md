# Final PDF: preserving provisional Ubuntu OSV evidence

This stage of [Issue #12](https://github.com/Danil-super/hardening-control-platform/issues/12)
projects optional original Trivy+Ubuntu OSV observations into the immutable
final project-report snapshot and the PDF export.

## Preservation and traceability

When a project report includes one or more source reports in
`mode=vulnerabilities`, the exporter reads their **original JSON findings**
directly rather than relying on deduplicated correlation findings.

The source report SHA-256 is already retained in `sourceManifest`. Each
candidate OSV record adds a machine-readable tuple containing:

- Source JSON report ID, SHA-256, and **original finding ID**.
- CVE, binary package and installed binary version.
- Source package and source version used in the OSV comparison.
- Original HCP/Trivy finding status and applicability verdict.
- OSV candidate verdict, status, reason, snapshot SHA-256 and Git revision.
- Conflict flag and explicit `trustedVerdict=unknown`,
  `publisherAuthenticated=false`, `remediationAuthorized=false`.

These items live in `vendorAdvisoryEvidence` in the separately stored
final-report JSON snapshot. `vendorAdvisoryEvidenceSha256` hashes the canonical
ordered projection, bound to the host alias. The overall PDF and snapshot
checksums remain governed by the HCP audited project-report record.

The PDF includes every projected CVE×package observation, source report ID,
original finding ID, source digests, competing conclusions and trust caveat.
Records are rendered as splittable paragraphs (not a giant unsplittable table),
preserving large evidence sets across pages.

## Fail-closed behavior

- The projector allows at most 4096 OSV observation tuples per project.
  Exceeding this bound **fails export explicitly**; it never silently lists
  only the first N records.
- Invalid source hashes, corrupted preview identities, duplicated finding IDs,
  attempts to claim authenticated publisher evidence or authorization to
  remediate are rejected rather than dropped from the report.
- No host mutation, OSV download, changes to Trivy finding status/coverage or
  vendor-attestation decisions occur during final PDF export.
- An original report without OSV previews continues to export normally.
- A report remains an evidence snapshot, not a full archive of Canonical
  advisory bytes. The external local snapshot vault must be retained
  separately; the PDF records its SHA-256 and revision.

## Validation

The unit contract test checks duplicate IDs, false claims of publisher trust,
source hash validation and overflow. The project-report regression test
constructs a saved original Trivy finding with a provisional conflicting
OSV result, builds the **real PDF renderer** and checks both saved JSON and
decompressed PDF page text for CVE and finding identities.

Native Linux acceptance and all affected project-report/PDF tests must pass
for the final PR commit before merging.
