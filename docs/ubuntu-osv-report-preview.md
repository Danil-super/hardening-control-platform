# Ubuntu OSV: optional CVE-report preview (Issue #12)

The Ubuntu OSV cross-check can now **annotate** selected Trivy package CVEs in
the original immutable report. This is opt-in and always non-authoritative.
Without the configuration below, existing scan behavior and JSON stay unchanged.

## Operator configuration

The control-node administrator may set the environment variable
`HCP_UBUNTU_OSV_PREVIEW_PINS_JSON` to a JSON object mapping an exact CVE ID to
the SHA-256 of an **already imported and stored** Canonical GitHub revision
snapshot. For example, replace the example hash with a real verified digest:

```json
{"CVE-2024-6119":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

Only CVE identifiers and lowercase 64-character SHA-256 values are allowed.
The JSON is limited to 24 KiB and 128 CVEs. It contains no arbitrary URLs.
The code never downloads anything during audit and uses the HCP state root
to read the immutable vault. The snapshot must include the Canonical
revision origin metadata recorded by the controlled import in PR #16.
Raw local snapshots without that source reference are not accepted as a
Canonical preview.

For each selected Trivy finding, HCP requires:
- exact `ID=ubuntu` and OS `VERSION_ID`;
- existing Trivy `sourceMatch=matched` and distribution-maintainer
  provenance observation;
- source package name and version from the installed package inventory;
- an exact CVE match and a pinned snapshot whose OSV release/source match.

The preview uses native `dpkg` version comparisons and records:
`candidateVerdict`, `trustedVerdict="unknown"`, source version, snapshot
SHA-256, Git revision and whether it contradicts Trivy. Each distinct
CVE×SHA×source×version is evaluated at most once, reused across DEB multiarch
findings, with a 512-evaluation hard limit.

## Safety and semantics

A candidate `fixed_or_not_affected` is **never** a confirmed vendor status.
The snapshot digest matches operator-selected bytes, not a Canonical
signature. Publisher authentication and freshness are not established here.

- Trivy finding IDs, risk, statuses, coverage and remediation flags do not
  change. A provisional disagreement is shown alongside the original result,
  not used to silently suppress a CVE.
- The saved CVE report includes a separate `vulnerabilityScan.ubuntuOsvPreview`
  summary and optional `finding.ubuntuOsvPreview` data.
- Missing, corrupted, local-only or unusable snapshots become
  `status=unavailable` with an `unknown` candidate.
- Invalid configuration is explicitly marked `invalid_catalog`; it cannot
  convert an incomplete scan into success.
- The browser shows these preliminary results separately with a warning.
  This phase does **not** authorize package remediation from OSV evidence.
- The final PDF and project report correlation still require independent
  cross-check-evidence preservation tests before they can be said to
  fully present the new preview.

The feature is for validation and operator investigation of discrepancies.
It does not establish completeness of the full vulnerability database or
independent provenance verification. Issue #12 remains open pending a
proper source trust policy, publish/refresh lifecycle, deeper vendor
advisory checks and PDF acceptance.

## Regression tests

`web/tests/trivy-accuracy.test.mjs` exercises the actual Trivy report
writer with a pinned OSV contract fixture to confirm both observations,
preserved native findings/coverage and correct saved JSON. It also covers
disabled mode, unverified local-only origin and invalid catalog.

All fixtures are synthetic and must not be described as live official
advisory or independent CVE-detection accuracy measurements.
