# Immutable local vendor advisory snapshot vault

**Scope:** a low-level local byte store, independent of any scanner or vendor
parser. It is the storage groundwork for Issue #12; it does **not** download
advisories or prove the publisher's identity.

## Invariants

- `importPinnedUbuntuOsvSnapshot` accepts only locally supplied UTF-8 JSON, an
  explicit `UBUNTU-CVE-YYYY-NNNN` identity and independently pinned SHA-256.
  The caller is responsible for acquiring/authenticating the source; a digest
  supplied alongside arbitrary JSON is **not sufficient** to establish trust.
- The store is content-addressed at
  `<HCP_STATE_DIR>/vendor-advisory-snapshots/v1/<sha256>.json` with a separate
  manifest. Paths come exclusively from the trusted HCP state root and validated
  hex digests, never from remote URL paths.
- New directories have mode 0700, files mode 0600. Symlinks, hardlinked files,
  public permissions, unexpectedly sized files, and changed files are rejected.
  Atomic hard-link publication prevents overwriting an existing immutable file.
- Raw bytes and manifest are both fsynced; the directory is synchronized.
  A crash between writing data and publishing its manifest leaves an incomplete,
  unusable record, which an identical pinned local import can repair.
- All successful reads recheck sizes, SHA-256, identity and manifest integrity.
  `publisherAuthenticated: false` and
  `importMethod: operator-pinned-local-sha256` must remain explicit.

## Deliberate limitations

- The store does **not** verify vendor signatures, web TLS origins, OSV
  schema semantics, advisory freshness, Debian/RPM/APK version ranges or the
  authenticity of an operator-supplied checksum.
- It is not exposed through a user-supplied URL/API and cannot modify target
  Linux hosts. It does not alter Trivy findings, scores or remediation.
- No automatic garbage collection or stale-lock deletion is attempted.
  Orphaned temporary files after sudden host power loss need an explicit safe
  maintenance procedure before the vault is enabled in production.
- This code is currently not connected to the Ubuntu OSV cross-check parser,
  which is implemented independently in PR #13.
- A complete source trust lifecycle also needs a bounded, authenticated,
  audited import workflow, policy-scoped reference records, and native VM
  acceptance before enabling any vendor cross-checks in reports.

Unit tests exercise digest pinning, idempotence, duplicate identities,
permissions, tampering, symlink refusal and interrupted manifest recovery.
