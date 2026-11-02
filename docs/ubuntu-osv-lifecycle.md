# Ubuntu OSV lifecycle and local-import age policy

This is a conservative stage of Issue #12, applied to the **optional, offline** Ubuntu OSV preview. It does not authorize remediation or change original Trivy findings.

## Distinct concepts

- **Record published/modified/withdrawn**: timestamps from the pinned OSV JSON. They describe the record at the imported Git revision.
- **ImportedAt**: local vault storage timestamp. It does **not** indicate when Canonical published or last updated the latest official dataset.
- **Revision**: full 40-hex source Git commit pinned in the immutable manifest. A revision pin does **not** establish a signed Canonical publisher identity.
- **Publisher currency**: remains **unverified**. A file downloaded today from a two-year-old revision is still a historical source.

The new `web/lib/ubuntu-osv-lifecycle.ts` checks UTC RFC3339 timestamps, correct calendar dates, future skew (maximum five minutes), publication not later than modification, withdrawal, mandatory modification date and existence of the pinned commit reference. It then compares local time since import with a bounded policy.

A withdrawn, future-dated, malformed, unpinned or expired local snapshot cannot produce an `affected` or `fixed_or_not_affected` candidate in the UI/report. The preview becomes `unavailable` with `candidateVerdict=unknown`, an explicit reason and lifecycle evidence. Trivy scanner status, risk, scope, severity and remediation flags remain unchanged.

A valid `import_window_ok` state means **only** that the local import age is within policy and the record dates passed sanity checks. Even in that state, `publisherFreshnessVerified=false`, `publisherAuthenticated=false`, `trustedVerdict=unknown`, and `remediationAuthorized=false`.

## Configuration

`HCP_UBUNTU_OSV_MAX_IMPORT_AGE_HOURS=168` (default seven days) sets the maximum local import age. Valid whole hours are **1–8760**. An invalid setting disables the optional preview with the explicit `invalid_policy` result; the Trivy audit itself continues. A missing or invalid CVE-to-SHA catalog also does not change Trivy results.

The environment variable is forwarded by Docker Compose and included in `.env.production.example`.

## Evidence preservation

For each annotated Trivy finding, lifecycle state, reason, record dates, import time and age remain in the saved JSON. The optional OSV counters include withdrawn, stale-import and invalid-timestamp cases.

The final project report projection also records lifecycle state, reason, modified date, withdrawn date and age when available. The PDF prints that provisional state and explicitly states that Canonical publisher currency is **not** confirmed. Historical reports without lifecycle evidence remain readable.

## Tests and scope

Regression cases cover valid local import, expired import, withdrawn CVE, future/invalid dates, malformed calendar dates, pinned Git revision, invalid settings, and real Trivy report writer preservation. These are deterministic fixtures, not signed Canonical data.

Outstanding: authenticated source policy and independent latest-revision checks, a reviewed refresh and rollback flow, Debian-specific advisory adapter, real live publisher/backport acceptance. A recent local import must never be represented as proof of globally current CVE coverage.
