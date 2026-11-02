# Canonical Ubuntu OSV: bounded revision-pinned HTTPS import

This stage of [Issue #12](https://github.com/Danil-super/hardening-control-platform/issues/12) adds a **programmatic building block**, not a public endpoint or a scheduled updater.

The controller now has `fetchPinnedCanonicalUbuntuOsv(...)` in
`web/lib/canonical-ubuntu-osv-fetch.ts`. It receives a strict
`UBUNTU-CVE-YYYY-NNNN`, an immutable 40-hex Git commit of the public Canonical
`ubuntu-security-notices` repository, and an **independently acquired**
SHA-256 digest of the intended JSON. It generates exactly:

`https://raw.githubusercontent.com/canonical/ubuntu-security-notices/<commit>/osv/cve/<year>/<UBUNTU-CVE-ID>.json`

There is no user-supplied URL. Redirects (including cross-origin), unexpected
status/content types, oversized `Content-Length`, streamed content above
8 MiB, invalid UTF-8, unsupported OSV schema, wrong CVE identity and missing
SHA-256 pins are rejected **before** the immutable vault is written.

The vault manifest optionally records the exact Canonical repository revision,
constructed URL and record path. This origin claim cannot be changed on a
subsequent import of the same bytes: a prior local-only snapshot is not silently
upgraded to a downloaded one. Reading the vault verifies that this provenance
structure matches the pinned CVE and commit; malformed paths are rejected.

## Trust model

This code requests the fixed official GitHub-hosted HTTPS endpoint with default
runtime CA validation; it does **not** check Canonical signatures, attest the
GitHub account, establish that the supplied commit and digest were independently
trusted, or prove that the vulnerability database is fresh or complete.

The manifest keeps `publisherAuthenticated=false`. A successful download
proves that the bytes match a caller-provided digest at a specific revision,
**not** that Canonical cryptographically endorsed them. The downstream
`ubuntu-pinned-crosscheck.ts` still returns `trustedVerdict="unknown"`,
`publisherFreshnessVerified=false` and `remediationAuthorized=false`.

Import requires operator/administrator-controlled inputs. **Do not wire this
function to arbitrary unauthenticated HTTP API arguments.** An operational
workflow must establish the trusted revision/digest externally, define release
scope and update cadence, and audit the import before exposing it in the UI.

## Tests and next steps

`web/tests/canonical-ubuntu-osv-fetch.test.mjs` uses deterministic in-memory
HTTP responses to test exact URL generation, redirect/refusal, digest mismatch,
wrong CVE, HTML, announced and streamed size limits, idempotence and
import → immutable read → OSV comparison while retaining unknown trusted status.

The test does **not** perform a live internet download or attest a real
publisher signature. The next stage should add a controlled, auditable
administrator-managed source configuration, authenticated acquisition policy,
refresh/rollback and offline fallback. Only then may the engine annotate CVE
reports with independently obtained advisory evidence, keeping disagreements
manual/partial and full raw/normalized/PDF evidence conservation.
