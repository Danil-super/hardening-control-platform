# Debian Security Tracker: preliminary CVE report preview (stage 4, Issue #12)

This change connects the already merged full Debian tracker snapshot reader (PR #22) and real-feed compatibility tests (PR #23) to a **strictly optional, read-only** annotation in ordinary Trivy CVE report JSON and the browser report UI.

## Operator selection

* HCP_DEBIAN_TRACKER_PREVIEW_SHA256: the exact 64-hex SHA-256 of an immutable **full** Debian tracker JSON snapshot already imported into the controller state directory. Empty/unset disables the preview. This is NOT a URL and never initiates an import.
* HCP_DEBIAN_TRACKER_MAX_IMPORT_AGE_HOURS: 1–8760 integer, default 168. This is the local snapshot capture age only; it cannot prove the current publisher revision.

These settings are supported by Docker Compose and the production env example. No public import endpoint, scheduler, remote retrieval, service refresh or host modification is added.

## Eligibility and bounded resource use

Only exact Debian operating system ID and consistent release pairs are currently considered: 11/bullseye, 12/bookworm and 13/trixie. Package inventory, Trivy database freshness and CVE scan coverage must be complete.

Eligible source observations must be from Trivy, identified by a CVE, with exact OS ID and version, native dpkg package manager, source name and native source version, a vendor-matched advisory datasource, and provenance consistent with the distribution's maintainer metadata. Consistency is an **heuristic**, not verified package signing or archive membership.

The full immutable snapshot is read and revalidated **once for the entire report** (up to the separate 128 MiB full-feed bound). Distinct CVE×source×installed source-version tuples are deduplicated. The maximum is 128 distinct comparisons, including proper dpkg backport ordering. If the comparison budget is exceeded, no annotations are published rather than silently truncating results.

Each derived per-CVE excerpt retains a SHA-256 linked to the exact full-feed digest, captured time and pin mode. A missing CVE or a missing source/release cannot imply unaffected. Invalid, expired or corrupted snapshot data means no preview, not a clean result.

## Outcome and trusted verdict

The preview stores a distinct per-finding `debianTrackerPreview` and report-level counter summary. It does not overwrite `cveApplicability`, IDs, severity, raw scanner status, risk, coverage, scores, recommendation or remediation privileges.

The only possible trusted verdict is `unknown`. Flags `publisherAuthenticated`, `publisherFreshnessVerified` and `remediationAuthorized` are always false, including when the candidate indicates a fixed source version. Differences from Trivy are visible as review warnings, not automatic vulnerability suppression or authorization to modify hosts.

Checks: `web/tests/debian-tracker-preview.test.mjs` covers fixed/affected/uncertain source versions, full+derived SHA links, mismatched release/datasource/third-party package, disabled mode, invalid pin/policy, corrupted/stale snapshot and budget overflow.

## Explicit remaining scope

This is only the CVE **JSON and browser report** stage. The immutable final project-report JSON and PDF now retain complete source-bound Debian CVE evidence, with independently checked exact-multiset preservation (see [debian-tracker-final-evidence.md](debian-tracker-final-evidence.md)). Correlation is intentionally not the source of that projection. Native Debian VM verification of the new final-export path remains separate work. There is no claim of Debian publisher signature authentication, up-to-date full CVE coverage or fully verified package provenance. No automatic package upgrades may be based on this candidate.

Official upstream documentation: https://security-team.debian.org/security_tracker.html and https://www.debian.org/security/.
