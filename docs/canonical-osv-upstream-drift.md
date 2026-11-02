# Canonical OSV: observation of current CVE-file drift

This stage of [Issue #12](https://github.com/Danil-super/hardening-control-platform/issues/12) adds a **read-only controller diagnostic** that compares an already imported immutable Ubuntu OSV snapshot with the same CVE file at a newly observed revision of Canonical's public GitHub repository.

The module is `web/lib/canonical-osv-upstream-check.ts`. It is not called from scheduled scans, the application UI, report exporters, OSV import or remediation. It must be invoked only by trusted operator/controller code. There is **no public endpoint or unattended refresh**.

## Exact observation

1. Read and verify the locally pinned snapshot (SHA-256, immutable manifest, Canonical revision and OSV schema) **before** network access.
2. Request only `https://api.github.com/repos/canonical/ubuntu-security-notices/branches/main`, with HTTPS, redirects disabled, credentials omitted, and a 32 KiB maximum.
3. Require exact branch name `main` and a 40-character Git SHA in the returned JSON.
4. Construct the raw OSV URL from the validated CVE and observed Git SHA, with no arbitrary host or pathname.
5. Retrieve the exact CVE bytes, bounded to 8 MiB, verify UTF-8 and OSV record identity, calculate SHA-256, and compare to the local snapshot.

The result is one of:

- `same_content_at_observed_head`: identical bytes at the GitHub branch revision seen during the check.
- `changed_content_at_observed_head`: bytes differ; the local revision should be reviewed for replacement.
- `missing_at_observed_head`: the specific CVE file was absent at the observed revision (not proof that the CVE does not apply).
- `unavailable`: a local file, GitHub API, transport, size, content-type, branch schema or OSV validation failed.

All outcomes include the observation time and available pinned/observed revision identifiers. The return object **always** has `publisherAuthenticated=false`, `publisherFreshnessVerified=false`, `trustedVerdict="unknown"` and `remediationAuthorized=false`. The result is never used to suppress Trivy vulnerabilities or mark any host fixed.

## Limitations and trust

This is a remote observation, **not independent cryptographic authentication of Canonical**. HTTPS and a GitHub API branch lookup authenticate the transport endpoint only under the runtime CA policy. The upstream repository owner and Git commit are not independently verified with a Canonical signing key.

The GitHub `main` branch can change immediately after it is observed; this is not proof of sustained freshness. Equality of one CVE record is **not** evidence that the whole advisory database is current, that all known CVEs are covered, or that vendor backports for a host are verified.

If a newer file differs, the immutable local snapshot remains unchanged. A separate, audited, pinned operator import and review is required before switching a report's source digest. No automatic refresh, retention policy, or rollback is implemented in this PR.

## Validation

`web/tests/canonical-osv-upstream-check.test.mjs` uses deterministic transport mocks to test identical/different CVE bytes, a deleted file, invalid local origin, wrong branch/revision, HTTP errors, redirects, streamed size limits, malformed records and timeouts. Tests deliberately do not claim live official publisher authentication.

Next steps: persistent bounded **observation** records tied to an import revision, operator review/approval, source trust policy and signed publisher verification where supported. These must precede any use of remote source observations as authoritative vulnerability conclusions.
