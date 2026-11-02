# Pinned Ubuntu OSV cross-check (staged read-only bridge)

This is the next incremental part of [Issue #12](https://github.com/Danil-super/hardening-control-platform/issues/12).

`web/lib/ubuntu-pinned-crosscheck.ts` composes two previously tested components:
- The content-addressed, immutable local advisory vault in `vendor-advisory-snapshot.ts`.
- The offline Ubuntu OSV source-package evaluator in `ubuntu-osv-crosscheck.ts`,
  which uses `dpkg --compare-versions`, never lexical or semver comparisons.

`evaluatePinnedUbuntuCrossCheck` reads the exact pinned bytes, checks the
manifest identity and SHA-256, validates the Ubuntu CVE schema and requires
`osId="ubuntu"`, the exact release, source package/version, and an explicit
complete source inventory. The local import time is **not** interpreted as
the Canonical advisory publication time.

## Contract and trust boundary

The returned `candidateVerdict` can be `affected`,
`fixed_or_not_affected`, `needs_review` or `unknown` based on the
pinned OSV record and native dpkg comparison.

**For every input,** `trustedVerdict` remains `unknown`,
`publisherAuthenticated=false`, `publisherFreshnessVerified=false`,
and `remediationAuthorized=false`. This is intentional: SHA-256 matches
an operator-selected digest, not an authenticated publisher. Even a
`fixed_or_not_affected` *candidate* is not a verified remediation outcome.

A missing/corrupt/invalid snapshot fails closed to `status=unavailable`
and an `unknown` candidate without disclosing local file paths. Anomalous
future import timestamps are rejected rather than used as current evidence.

## Tested

`web/tests/ubuntu-pinned-crosscheck.test.mjs` exercises the complete
import → private stored bytes → verified read → OSV parser → real dpkg
comparison using synthetic but schema-shaped records. It includes vulnerable
and fixed Ubuntu source versions (including backport and epoch), wrong OS,
missing inventory, source/binary mismatch, unlisted suite, no fixed event,
on-disk tampering and future import timestamp.

## Remaining before production

The bridge is deliberately not called by the CVE scan scheduler, report
normalizer, UI or final PDF. This avoids presenting an unauthenticated local
JSON file as an independent vendor fix.

The next stage must independently establish trusted acquisition of Canonical
data (fixed HTTPS origin, bounded and audited update, explicit publication
metadata and/or signed publisher attestation), versioned schema compatibility,
freshness and source-package provenance, then propagate paired Trivy+vendor
observations across JSON/report/UI/PDF with disagreement marked `manual/partial`.
Do not authorize host changes based on this module alone.
