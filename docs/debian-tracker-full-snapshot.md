# Debian Security Tracker: immutable full-export capture (stage 2 of #12)

**Scope:** controller-only library and deterministic regression tests. This stage adds no public endpoint, scheduler, live UI, export integration, host modification, auto-update or CVE-based remediation. The previous one-CVE evaluator remains provisional.

## Why separate from Ubuntu snapshots?

Debian provides a single complete JSON export at the **fixed** official address
https://security-tracker.debian.org/tracker/data/json . It is larger than the
8 MiB Ubuntu per-CVE immutable vault bound; a separate 64 MiB ceiling protects
the controller against an unexpectedly large response. Debian explicitly calls
the JSON export an **unstable interface**. Its source package, CVE, per-release,
status and fixed_version semantics require an independently versioned adapter.

Implementation: web/lib/debian-tracker-snapshot.ts .
Tests: web/tests/debian-tracker-snapshot.test.mjs .

## Download boundary

importDebianTrackerFullSnapshot:
1. Requests only the compile-time fixed HTTPS endpoint (no URL accepted as input).
2. Uses GET, credentials omitted, redirects disabled, no cache, and an AbortSignal
   timeout of 60 seconds. Requires HTTP 200, application/json and no Content-Range.
3. Rejects oversized or invalid Content-Length before reading and bounds the
   actual streamed body to 64 MiB regardless of headers.
4. Verifies UTF-8, valid JSON, duplicate object keys (including escaped equivalent
   keys), source-package and CVE release-map schema, bounded counts.
5. Optionally requires an **independently supplied SHA-256**. Without this pin
   the digest is only an observation of bytes obtained during the download.
6. Only after validation writes immutable content-addressed raw bytes and a
   machine-readable manifest in a private HCP state subdirectory. Data and
   manifest use no-follow read/write, fsync, link-based no-overwrite publication,
   strict private modes and stat checks on every subsequent read.

Manifest records: exact source URL, byte SHA-256 and size, capture time,
issue/source-package counts, adapter format and pin mode. Capture time is
**not** Debian's publication time, and a recently captured file does not
prove the publisher has produced fresh data.

Existing raw bytes/manifest are never silently overwritten or timestamp-refreshed.
An interrupted write may be retried with *identical* input and capture metadata;
the original immutable data is not deleted. A corrupt/replaced/public/symlinked
file fails closed.

## Derived CVE excerpt

evaluatePinnedDebianTrackerFullSnapshot:
- Reads and revalidates the **complete** immutable raw feed with its manifest,
  not a free-standing operator-supplied CVE fragment.
- Requires exact Debian OS identity, caller-asserted complete source inventory,
  exact source package, CVE and release codename, plus native dpkg source version.
  Kali, Ubuntu and Astra must never inherit Debian verdicts.
- Checks local capture-age policy (default seven days, configurable 1–8760h),
  rejects future timestamps and missing or corrupt snapshots.
- Extracts one exact source/CVE subtree, constructs a one-CVE excerpt and verifies
  its own SHA-256 using the stage-1 evaluator.
- Returns **both** full-feed SHA-256 and derived-excerpt SHA-256, so evidence can
  be traced back to specific full bytes. Missing CVE/source/release means unknown,
  not a clean scan. Version comparisons use native dpkg rather than lexicographic
  or semver ordering. The tracker repositories field is never a fixed version.

**For all paths, including fixed-version candidates:**
trustedVerdict=unknown,
publisherAuthenticated=false,
publisherFreshnessVerified=false,
remediationAuthorized=false.

Neither HTTPS transport nor SHA-256 of operator-pinned/downloaded bytes is a
Debian publisher signature or authenticated repository package provenance.
No Trivy finding is suppressed. This is a read-only, provisional comparison.

## Validation

CI runs synthetic full-export-shaped examples, including Debian 12
CVE-2024-6119 for openssl, before/after the 3.0.14-1~deb12u2 fixed version,
epoch/backports, other releases, unmatched source binaries, 404s/redirects,
wrong MIME, oversized stream, duplicate JSON keys, corrupt immutable data,
symlink replacement, interrupted import and stale/future capture times.

This stage **does not fetch and validate a real live Debian feed in CI** and
therefore cannot establish acceptance of every upstream entry. The published
full export is a moving target and may require further shape compatibility
work using controlled real-feed fixtures. There is intentionally no
browser-facing fetch or operational automatic refresh yet.

## Remaining before use in normal CVE reports

1. Add an operator-only import orchestration/CLI with a verified explicit state
   location, retention and approval of changed immutable hashes; never let a
   user supply arbitrary URLs.
2. Add controlled real-feed acceptance with the actual Debian source data,
   carefully bounded resource usage, verified source-package provenance, and
   review of schema mismatches/duplicate issue identities.
3. Authenticate Debian publisher provenance wherever supported; define policy
   for unsupported signing without equating HTTPS with a signed advisory.
4. Bind findings to host OS release, package source inventory, scanner provenance,
   and source repository identity; add disagreement handling and independent
   exact-multiset preservation in normalization, saved JSON and PDF.
5. Only after native VM verification on a single commit should UI expose the
   provisional vendor comparison; CVE candidate alone must **never** authorize
   an unattended package modification.

Official reference: https://security-team.debian.org/security_tracker.html
and https://www.debian.org/security/ .
