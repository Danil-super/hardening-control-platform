import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import test from "node:test";
import { compileServerModules } from "./_typescript-loader.mjs";

const compiled = compileServerModules(["debian-tracker-crosscheck"]);
const { parseDebianTrackerExcerpt, evaluateDebianTrackerExcerpt, DEBIAN_TRACKER_EXCERPT_MAX_BYTES } =
  await import(compiled.url("debian-tracker-crosscheck"));
test.after(() => rmSync(compiled.directory, { recursive: true, force: true }));

// Synthetic excerpt shaped like Debian's data/json export. This is NOT a
// publisher-authenticated feed or a complete distribution advisory.
function sample({ status = "resolved", fixed = "3.0.14-1~deb12u2", release = "bookworm" } = {}) {
  return {
    openssl: {
      "CVE-2024-6119": {
        description: "Synthetic regression fixture",
        releases: {
          [release]: {
            status, fixed_version: fixed,
            repositories: { bookworm: "9.9.99-not-a-fixed-version" },
            urgency: "high",
          },
        },
      },
    },
  };
}
function parse(value) {
  const raw = JSON.stringify(value);
  return parseDebianTrackerExcerpt(raw, createHash("sha256").update(raw).digest("hex"));
}
function check(snapshot, overrides = {}) {
  return evaluateDebianTrackerExcerpt(snapshot, {
    osId: "debian", inventoryComplete: true, cveId: "CVE-2024-6119",
    release: "bookworm", sourcePackage: "openssl", sourceVersion: "3.0.14-1~deb12u1",
    ...overrides,
  });
}
function safe(result) {
  assert.equal(result.trustedVerdict, "unknown");
  assert.equal(result.publisherAuthenticated, false);
  assert.equal(result.publisherFreshnessVerified, false);
  assert.equal(result.remediationAuthorized, false);
}

test("Debian 12 backported source versions use dpkg order, never a repository candidate version", () => {
  const snapshot = parse(sample());
  for (const [sourceVersion, verdict] of [
    ["3.0.14-1~deb12u1", "affected"],
    ["3.0.14-1~deb12u2", "fixed_or_not_affected"],
    ["3.0.14-1~deb12u10", "fixed_or_not_affected"],
    ["3.0.14~rc1-1~deb12u2", "affected"],
    ["1:3.0.14-1~deb12u1", "fixed_or_not_affected"],
  ]) {
    const result = check(snapshot, { sourceVersion });
    assert.equal(result.status, "provisional");
    assert.equal(result.candidateVerdict, verdict);
    assert.equal(result.fixedVersion, "3.0.14-1~deb12u2");
    safe(result);
  }
});

test("tracker status and special fixed_version 0 are distinct, ambiguous inputs never imply a fix", () => {
  const unaffected = check(parse(sample({ fixed: "0" })));
  assert.equal(unaffected.candidateVerdict, "fixed_or_not_affected");
  assert.equal(unaffected.reason, "tracker_explicit_not_affected_sentinel");
  safe(unaffected);
  for (const [record, verdict] of [
    [sample({ status: "open", fixed: null }), "needs_review"],
    [sample({ status: "undetermined", fixed: null }), "needs_review"],
    [sample({ status: "open", fixed: "0" }), "needs_review"],
    [sample({ status: "resolved", fixed: null }), "unknown"],
    [sample({ status: "new-status", fixed: "0" }), "unknown"],
  ]) {
    const result = check(parse(record));
    assert.equal(result.candidateVerdict, verdict);
    safe(result);
  }
});

test("only exact Debian release, CVE and source-package inventory may be evaluated", () => {
  const snapshot = parse(sample());
  for (const [overrides, reason] of [
    [{ osId: "ubuntu" }, "unsupported_exact_os_identity"],
    [{ osId: "kali" }, "unsupported_exact_os_identity"],
    [{ inventoryComplete: false }, "incomplete_source_inventory"],
    [{ cveId: "CVE-2024-6120" }, "cve_identity_mismatch"],
    [{ release: "trixie" }, "source_release_not_listed"],
    [{ release: "bookworm-security" }, "source_release_not_listed"],
    [{ sourcePackage: "libssl3" }, "source_package_mismatch"],
    [{ sourceVersion: "3.0.14-1;sh" }, "invalid_target_identity"],
  ]) {
    const result = check(snapshot, overrides);
    assert.equal(result.status, "unavailable");
    assert.equal(result.candidateVerdict, "unknown");
    assert.equal(result.reason, reason);
    safe(result);
  }
});

test("excerpt parser enforces independent digest, size and source/CVE shape", () => {
  const raw = JSON.stringify(sample());
  assert.throws(() => parseDebianTrackerExcerpt(raw, "0".repeat(64)), /differs/);
  assert.throws(() => parseDebianTrackerExcerpt(raw, "bad-digest"), /SHA-256/);
  assert.throws(() => parseDebianTrackerExcerpt("a".repeat(DEBIAN_TRACKER_EXCERPT_MAX_BYTES + 1), "a".repeat(64)), /size/);
  assert.throws(() => parse({ openssl: {}, bash: {} }), /exactly one valid source package/);
  assert.throws(() => parse({ openssl: { "CVE-2024-6119": sample().openssl["CVE-2024-6119"],
    "CVE-2024-6120": sample().openssl["CVE-2024-6119"] } }), /exactly one CVE/);
  assert.throws(() => parse({ openssl: { "CVE-2024-6119": { releases: [] } } }), /CVE entry/);
  assert.throws(() => parse({ openssl: { "CVE-2024-6119": { releases: { bookworm: null } } } }), /releases schema/);
});

test("unsupported/malformed tracker release entries fail closed", () => {
  const invalidVersion = check(parse(sample({ fixed: "not;a;version" })));
  assert.equal(invalidVersion.candidateVerdict, "unknown");
  assert.equal(invalidVersion.reason, "resolved_without_valid_fixed_version");
  safe(invalidVersion);
  const unknownStatus = check(parse(sample({ status: 100 })));
  assert.equal(unknownStatus.candidateVerdict, "unknown");
  safe(unknownStatus);
  const missing = sample();
  delete missing.openssl["CVE-2024-6119"].releases.bookworm.fixed_version;
  assert.equal(check(parse(missing)).candidateVerdict, "unknown");
});
