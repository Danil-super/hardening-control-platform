# Read-only Debian Security Tracker excerpt cross-check (stage 1)

This is a staged part of Issue #12. It deliberately adds **no** scheduled scan, network downloader, persisted vendor verdict, PDF claim, public endpoint, or remediation. The library is web/lib/debian-tracker-crosscheck.ts and the tests are web/tests/debian-tracker-crosscheck.test.mjs.

## Input contract and publisher boundary

Debian Security Tracker publishes a large JSON document at https://security-tracker.debian.org/tracker/data/json. Debian explicitly says this export is **not a stable public API**. It is keyed by Debian **source package**, then CVE, then release. This first-stage adapter accepts only a **bounded 128 KiB, one-source-package/one-CVE JSON excerpt**, retaining the original nesting, with an operator-provided SHA-256. It does not download, parse, attest, or store the full upstream export, and the excerpt's digest is **not** a digest of the complete feed. Extraction and supply-chain provenance are not independently authenticated.

A candidate evaluation requires exact osId=debian, complete caller-reported source inventory, source package, CVE, release codename and installed source version. Binary package names must not substitute for source names. Releases and repository versions are not interchangeable. Unsupported OS identities, absent or ambiguous data and malformed input return unknown, never clean.

## Candidate version semantics

- status=resolved and fixed_version=<a valid dpkg version>: use native /usr/bin/dpkg --compare-versions with argv (never shell), supporting epoch, tilde and deb12u backports. Before the fixed version is a candidate affected result; at/after it is candidate fixed_or_not_affected.
- status=resolved and fixed_version=0: Debian's documented special case for *not affected*, distinct from version zero.
- status=open or undetermined: needs_review, even if fixed_version appears to exist.
- Missing, unsupported or inconsistent status/fixed version: unknown, not a fixed outcome.
- repositories is **not** a fixed-version source. It may represent what is available in archives, not the correction threshold.

All outputs retain trustedVerdict=unknown, publisherAuthenticated=false, publisherFreshnessVerified=false and remediationAuthorized=false. Even a candidate fixed_or_not_affected result cannot clear a Trivy finding or authorize host changes. Exact source-package provenance is not attested by a copied excerpt.

## Reproducible tests and limitations

Synthetic tests cover CVE-2024-6119/openssl for Debian 12 bookworm, source versions before/at/after 3.0.14-1~deb12u2, epochs, tilde, status=0 semantics, contradictions, wrong distribution, missing release, binary-vs-source mismatch, bad digest, malformed schema and size bounds. The official DSA-5764-1 identifies this CVE and fixed version, but test records are constructed fixtures, not downloaded advisories.

Run from web: npm test (Node 24 in CI) or node --test tests/debian-tracker-crosscheck.test.mjs.

## Required next stages before product integration

1. Implement a separately versioned, bounded, provenance-preserving importer for the **full** Debian tracker export (currently larger than the 8 MiB Ubuntu OSV vault bound), with fixed HTTPS origin, schema-change handling, publisher trust assessment, digest, capture time and immutable atomic publication.
2. Produce a demonstrably faithful per-CVE subset of an immutable full-feed snapshot, including source SHA and provenance; validate missing/duplicate package/CVE keys and require a freshness policy.
3. Bind the controller's real OS/source-package inventory, installed Debian source version and exact distribution suite. Verify genuine origin/apt provenance independently; handle backports and derivatives explicitly.
4. Compare with Trivy without overwriting raw findings. Preserve conflicts and unknowns through report, normalized JSON, UI and final PDF; fail closed on record loss. Test on native Debian VMs with real vendor records at one exact commit.
5. Never permit automatic remediation solely on the preliminary tracker candidate.

References: https://security-team.debian.org/security_tracker.html and https://www.debian.org/security/ and https://lists.debian.org/debian-security-announce/2024/msg00177.html .
