# Offline Ubuntu OSV evaluator (stage 1 of Issue #12)

**Status: isolated library and fixture tests only.** This module is not wired
to live CVE reports, scheduled scans, user-facing conclusions or remediation.
Do not describe it as independent vendor verification until a pinned vendor
snapshot import, publisher authentication, actual host binding and native VM
acceptance are complete.

The `web/lib/ubuntu-osv-crosscheck.ts` library interprets the official
[Canonical Ubuntu OSV schema](https://documentation.ubuntu.com/security/security-updates/osv/)
conservatively. Ubuntu's record describes **source packages**, not necessarily
the binary package name that Trivy reports.

## Safe input / boundaries

- Only manually supplied in-memory JSON with an externally pinned SHA-256 is
  parsed. A matching digest proves byte identity with **that pinned value**,
  not producer identity or trust. There are no HTTP requests or file writes.
- A record must be `UBUNTU-CVE-...` with matching `upstream` CVE ID, OSV
  schema major version 1 and a bounded JSON payload (up to 8 MiB).
- The exact `Ubuntu:<release>:LTS` ecosystem and **source package name**
  must match the query. An Ubuntu Pro/Esm record is not silently interpreted as
  a standard archive record. Missing release/source evidence gives `unknown`,
  not a clean result.
- With a Canonical fixed source version and the documented
  `introduced: "0"` range, the evaluator calls **native dpkg** version
  comparison on the controller (`/usr/bin/dpkg --compare-versions`) with
  argv, no shell. This handles epoch, tilde, and Ubuntu backport revisions.
- If Canonical supplies no `fixed` event, an exact listed affected source
  version yields `affected`; an unlisted version remains `unknown`.
- Malformed or unsupported ranges, duplicate suite/source entries, missing
  native comparator and version ambiguity fail closed (`unknown` or
  `needs_review`), not `fixed`.

The `fixed_or_not_affected` verdict means the source version is at or above
the published **fixed version for the selected record**. It does **not** imply
all CVEs for that package are patched or that the host is secure.

## Tests

`web/tests/ubuntu-osv-crosscheck.test.mjs` uses synthetic OSV-shaped examples
for CVE-2024-6119/openssl in Ubuntu 24.04 to check before/after fixed
backports, Debian epoch/tilde semantics, source vs binary names, release
separation, unsigned digest boundary, absent fixed events and malformed data.
These fixtures are **not downloaded vendor advisories**.

## Requirements for stage 2

- Authenticated, bounded vendor snapshot import with immutable raw bytes,
  source digest, fetched timestamp, schema version, signature/trust evidence
  and a clear offline freshness policy.
- Snapshot selection by actual OS release, CVE and source package, then match
  to inventory `sourceName/sourceVersion`; unknown origin/ESM scope must remain
  explicit. No arbitrary URL fetches or automatic attachment to unrelated
  package managers.
- Compare real native Debian/Ubuntu VM vulnerable/fixed pairs and label any
  disagreement with Trivy. Extend persisted reports, normalizer, PDF and UI.
- No automatic package updates authorized solely by this evaluator.

For Debian, the Security Tracker JSON export is a separate schema adapter;
it is documented by Debian as not a stable public API. Do **not** reuse the
Ubuntu OSV parser for Debian.
