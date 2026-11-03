import { createHash, randomUUID } from "node:crypto";
import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, linkSync, lstatSync,
  mkdirSync, openSync, readSync, rmSync, writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  parseDebianTrackerExcerpt, evaluateDebianTrackerExcerpt,
  type DebianTrackerEvaluation,
} from "@/lib/debian-tracker-crosscheck";

/**
 * Controller-only, opt-in import. Importing the exact public HTTPS endpoint is
 * NOT cryptographic authentication of Debian's publication. Nothing here is
 * connected to scan jobs, public HTTP routes, UI or remediation.
 */
export const DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json";
// Bounded DECODED bytes: Node fetch transparently inflates Debian's gzip stream.
// Verified Nov 3 2026 feed was 87,754,048 decoded bytes (14,441,247 wire bytes).
export const DEBIAN_TRACKER_MAX_BYTES = 128 * 1024 * 1024;
export const DEBIAN_TRACKER_FULL_FORMAT = "debian-tracker-full-json-v1";
const SHA = /^[a-f0-9]{64}$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;
const SOURCE = /^[a-z0-9][a-z0-9+.-]*$/;
const RELEASE = /^[a-z][a-z0-9-]*$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const MAX_PACKAGES = 250_000;
const MAX_ISSUES = 2_000_000;

type JsonRecord = Record<string, unknown>;

export type DebianTrackerFullManifest = {
  schemaVersion: 1;
  format: typeof DEBIAN_TRACKER_FULL_FORMAT;
  sourceUrl: typeof DEBIAN_TRACKER_URL;
  sha256: string;
  bytes: number;
  capturedAt: string;
  sourcePackageCount: number;
  issueCount: number;
  transport: "https-fixed-origin-no-redirects";
  pinMode: "independently-specified-sha256" | "observed-at-capture";
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
};

export type DebianTrackerStoredEvaluation = {
  schemaVersion: 1;
  status: "provisional" | "unavailable";
  reason: string;
  candidateVerdict: DebianTrackerEvaluation["candidateVerdict"];
  trustedVerdict: "unknown";
  fullSnapshotSha256: string | null;
  derivedExcerptSha256: string | null;
  sourcePackage: string;
  cveId: string;
  release: string;
  importedAt: string | null;
  localImportAgeHours: number | null;
  fixedVersion: string | null;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
};

function record(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function utcTimestamp(value: unknown): value is string {
  return typeof value === "string" && UTC.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Detect duplicate JSON keys, including escaped equivalent keys, before JSON.parse discards them. */
function rejectDuplicateObjectKeys(raw: string): void {
  const stack: Array<{ kind: "object" | "array"; keys?: Set<string> }> = [];
  for (let index = 0; index < raw.length; index++) {
    const character = raw[index];
    if (character === '"') {
      const start = index;
      index++;
      let escaped = false;
      for (; index < raw.length; index++) {
        const next = raw[index];
        if (!escaped && next === '"') break;
        if (!escaped && next === "\\") escaped = true;
        else escaped = false;
      }
      if (index >= raw.length) throw new Error("Invalid Debian tracker JSON string");
      let after = index + 1;
      while (after < raw.length && /[\t\n\r ]/.test(raw[after])) after++;
      if (raw[after] === ":") {
        const container = stack[stack.length - 1];
        if (!container || container.kind !== "object") throw new Error("Unexpected Debian tracker JSON key");
        const key: string = JSON.parse(raw.slice(start, index + 1));
        if (container.keys!.has(key)) throw new Error("Duplicate Debian tracker JSON key");
        container.keys!.add(key);
      }
      continue;
    }
    if (character === "{") stack.push({ kind: "object", keys: new Set() });
    else if (character === "[") stack.push({ kind: "array" });
    else if (character === "}" || character === "]") stack.pop();
  }
}

function parseFullExport(rawJson: string): { data: JsonRecord; packages: number; issues: number } {
  rejectDuplicateObjectKeys(rawJson);
  const parsed: unknown = JSON.parse(rawJson);
  if (!record(parsed)) throw new Error("Debian tracker export root is not an object");
  const sourcePackages = Object.keys(parsed);
  if (sourcePackages.length < 1 || sourcePackages.length > MAX_PACKAGES) {
    throw new Error("Debian tracker source package count outside bounds");
  }
  let issues = 0;
  for (const name of sourcePackages) {
    if (name.length > 180 || !SOURCE.test(name) || !record(parsed[name])) {
      throw new Error("Debian tracker source package schema unsupported");
    }
    const items = parsed[name] as JsonRecord;
    for (const identifier of Object.keys(items)) {
      if (++issues > MAX_ISSUES || identifier.length > 96 || !/^[A-Z][A-Z0-9-]+$/.test(identifier)
        || !record(items[identifier])) {
        throw new Error("Debian tracker issue schema or size unsupported");
      }
      const item = items[identifier] as JsonRecord;
      // The upstream export also contains non-CVE identifiers. Validate every
      // CVE's release map, but preserve other entries without granting verdicts.
      if (CVE.test(identifier)) {
        if (!record(item.releases) || Object.keys(item.releases).length > 32
          || Object.entries(item.releases).some(([release, detail]) =>
            release.length > 32 || !RELEASE.test(release) || !record(detail))) {
          throw new Error("Debian tracker CVE release schema unsupported");
        }
      }
    }
  }
  return { data: parsed, packages: sourcePackages.length, issues };
}

function stateDirectory(root: string): string {
  const rootInfo = lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("Invalid HCP state root");
  const parent = path.join(root, "debian-tracker-snapshots");
  const directory = path.join(parent, "v1");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  for (const current of [parent, directory]) {
    const info = lstatSync(current);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) {
      throw new Error("Debian tracker snapshot directories must be private");
    }
  }
  return directory;
}

function pathsFor(root: string, digest: string) {
  if (!SHA.test(digest)) throw new Error("Invalid Debian tracker snapshot digest");
  const directory = stateDirectory(root);
  return {
    directory,
    data: path.join(directory, digest + ".json"),
    manifest: path.join(directory, digest + ".manifest.json"),
  };
}

function syncDirectory(directory: string): void {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function atomicPublish(directory: string, destination: string, data: Buffer): void {
  const temporary = path.join(directory, ".debian-tracker-" + randomUUID() + ".tmp");
  try {
    const fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | O_NOFOLLOW, 0o600);
    try {
      fchmodSync(fd, 0o600);
      writeFileSync(fd, data);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    try { linkSync(temporary, destination); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    syncDirectory(directory);
  } finally { rmSync(temporary, { force: true }); }
}

/** Strict bounded no-follow read; reject replacement, public files, hard links and FIFO/device nodes. */
function privateFile(filename: string, limit: number): Buffer {
  const fd = openSync(filename, constants.O_RDONLY | O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== BigInt(1) || (before.mode & BigInt(0o077)) !== BigInt(0)
      || before.size < BigInt(1) || before.size > BigInt(limit)) {
      throw new Error("Debian tracker file type, permissions or size invalid");
    }
    const output = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < output.length) {
      const received = readSync(fd, output, length, Math.min(64 * 1024, output.length - length), null);
      if (!received) break;
      length += received;
    }
    const after = fstatSync(fd, { bigint: true });
    const pathname = lstatSync(filename, { bigint: true });
    for (const property of ["dev", "ino", "size", "mtimeNs", "ctimeNs", "nlink"] as const) {
      if (before[property] !== after[property] || after[property] !== pathname[property]) {
        throw new Error("Debian tracker snapshot changed during read");
      }
    }
    if (!pathname.isFile() || length !== Number(before.size)) {
      throw new Error("Debian tracker snapshot changed size");
    }
    return output.subarray(0, length);
  } finally { closeSync(fd); }
}

function decodeUtf8(bytes: Buffer): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/**
 * Lightweight controller-only status: validates private manifest shape but
 * does NOT read the full archive. Approval and scans must always verify bytes.
 */
export function readDebianTrackerSnapshotManifest(root: string, digest: string): DebianTrackerFullManifest {
  const locations = pathsFor(root, digest);
  const parsedManifest: unknown = JSON.parse(decodeUtf8(privateFile(locations.manifest, 4096)));
  if (!record(parsedManifest)) throw new Error("Invalid Debian tracker manifest");
  const m = parsedManifest as DebianTrackerFullManifest;
  if (m.schemaVersion !== 1 || m.format !== DEBIAN_TRACKER_FULL_FORMAT
    || m.sourceUrl !== DEBIAN_TRACKER_URL || m.transport !== "https-fixed-origin-no-redirects"
    || !["independently-specified-sha256", "observed-at-capture"].includes(m.pinMode)
    || m.publisherAuthenticated !== false || m.publisherFreshnessVerified !== false
    || m.remediationAuthorized !== false || m.sha256 !== digest
    || !Number.isSafeInteger(m.bytes) || m.bytes < 2 || m.bytes > DEBIAN_TRACKER_MAX_BYTES
    || !utcTimestamp(m.capturedAt) || !Number.isSafeInteger(m.sourcePackageCount)
    || !Number.isSafeInteger(m.issueCount)) {
    throw new Error("Invalid or unsupported Debian tracker snapshot manifest");
  }
  return m;
}

export function readPinnedDebianTrackerFullSnapshot(root: string, digest: string): {
  manifest: DebianTrackerFullManifest;
  data: JsonRecord;
} {
  const locations = pathsFor(root, digest);
  const m = readDebianTrackerSnapshotManifest(root, digest);
  const bytes = privateFile(locations.data, DEBIAN_TRACKER_MAX_BYTES);
  if (bytes.length !== m.bytes || sha256(bytes) !== digest) {
    throw new Error("Debian tracker full snapshot integrity mismatch");
  }
  const parsed = parseFullExport(decodeUtf8(bytes));
  if (parsed.packages !== m.sourcePackageCount || parsed.issues !== m.issueCount) {
    throw new Error("Debian tracker manifest inventory mismatch");
  }
  return { manifest: m, data: parsed.data };
}

/** A fixed-origin, bounded download. No user URL, redirect, credentials or automatic refresh. */
export async function importDebianTrackerFullSnapshot(input: {
  stateRoot: string;
  expectedSha256?: string;
  fetchImpl?: typeof fetch;
  now?: string;
  /** Preserve the original capture timestamp when identical bytes are fetched again. */
  reuseIdenticalSnapshot?: boolean;
}): Promise<DebianTrackerFullManifest> {
  if (input.expectedSha256 !== undefined && !SHA.test(input.expectedSha256)) {
    throw new Error("Invalid operator-pinned Debian tracker SHA-256");
  }
  const capturedAt = input.now ?? new Date().toISOString();
  if (!utcTimestamp(capturedAt) || Date.parse(capturedAt) > Date.now() + 5 * 60_000) {
    throw new Error("Invalid Debian tracker capture time");
  }
  const downloader = input.fetchImpl ?? fetch;
  const response = await downloader(DEBIAN_TRACKER_URL, {
    method: "GET", redirect: "error", credentials: "omit", cache: "no-store",
    headers: { Accept: "application/json" }, signal: AbortSignal.timeout(60_000),
  });
  if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")
    || response.headers.has("content-range") || !response.body) {
    throw new Error("Debian tracker download has unsupported status or content type");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > DEBIAN_TRACKER_MAX_BYTES)) {
    throw new Error("Debian tracker declared download size invalid");
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > DEBIAN_TRACKER_MAX_BYTES) throw new Error("Debian tracker streamed size exceeds limit");
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  if (total < 2) throw new Error("Debian tracker download is empty");
  const bytes = Buffer.concat(chunks, total);
  const digest = sha256(bytes);
  if (input.expectedSha256 !== undefined && digest !== input.expectedSha256) {
    throw new Error("Debian tracker downloaded bytes differ from operator pin");
  }
  const validated = parseFullExport(decodeUtf8(bytes));
  // No writes until transport, UTF-8, duplicate-key, schema and optional pin validation.
  const locations = pathsFor(input.stateRoot, digest);
  atomicPublish(locations.directory, locations.data, bytes);
  const manifest: DebianTrackerFullManifest = {
    schemaVersion: 1, format: DEBIAN_TRACKER_FULL_FORMAT,
    sourceUrl: DEBIAN_TRACKER_URL, sha256: digest, bytes: total, capturedAt,
    sourcePackageCount: validated.packages, issueCount: validated.issues,
    transport: "https-fixed-origin-no-redirects",
    pinMode: input.expectedSha256 ? "independently-specified-sha256" : "observed-at-capture",
    publisherAuthenticated: false, publisherFreshnessVerified: false,
    remediationAuthorized: false,
  };
  atomicPublish(locations.directory, locations.manifest, Buffer.from(JSON.stringify(manifest), "utf8"));
  const observed = readPinnedDebianTrackerFullSnapshot(input.stateRoot, digest);
  // Re-import of an existing digest is allowed only if its origin and metadata
  // claims are identical; no "freshening" of an old snapshot via a new timestamp.
  if (JSON.stringify(observed.manifest) !== JSON.stringify(manifest)) {
    // Identical bytes may be observed again, but their ORIGINAL local capture
    // timestamp cannot be refreshed. Never upgrade from an observed hash to an
    // independently pinned or publisher-verified source without a new record.
    if (input.reuseIdenticalSnapshot === true && observed.manifest.pinMode === manifest.pinMode
      && observed.manifest.sha256 === manifest.sha256) return observed.manifest;
    throw new Error("Existing immutable Debian tracker manifest differs from this import");
  }
  return observed.manifest;
}

/** Derive a CVE excerpt from the verified full-feed bytes and retain BOTH hashes. */
export function evaluatePinnedDebianTrackerFullSnapshot(input: {
  stateRoot: string;
  snapshotSha256: string;
  osId: string;
  inventoryComplete: boolean;
  sourcePackage: string;
  sourceVersion: string;
  cveId: string;
  release: string;
  now?: string;
  maxImportAgeHours?: number;
}): DebianTrackerStoredEvaluation {
  const base: DebianTrackerStoredEvaluation = {
    schemaVersion: 1, status: "unavailable", reason: "insufficient_vendor_evidence",
    candidateVerdict: "unknown", trustedVerdict: "unknown",
    fullSnapshotSha256: null, derivedExcerptSha256: null,
    sourcePackage: input.sourcePackage, cveId: input.cveId, release: input.release,
    importedAt: null, localImportAgeHours: null, fixedVersion: null,
    publisherAuthenticated: false, publisherFreshnessVerified: false, remediationAuthorized: false,
  };
  // Reject unknown OS/source identity before reading any snapshot bytes.
  if (input.osId !== "debian") return { ...base, reason: "unsupported_exact_os_identity" };
  if (input.inventoryComplete !== true) return { ...base, reason: "incomplete_source_inventory" };
  if (!SOURCE.test(input.sourcePackage) || input.sourcePackage.length > 180
    || !CVE.test(input.cveId) || input.cveId.length > 32
    || !RELEASE.test(input.release) || input.release.length > 32
    || !/^[A-Za-z0-9.+~:-]{1,256}$/.test(input.sourceVersion)) {
    return { ...base, reason: "invalid_target_identity" };
  }
  const maxAgeHours = input.maxImportAgeHours ?? 168;
  if (!Number.isInteger(maxAgeHours) || maxAgeHours < 1 || maxAgeHours > 8760) {
    return { ...base, reason: "invalid_local_import_age_policy" };
  }
  const now = input.now ?? new Date().toISOString();
  if (!utcTimestamp(now)) return { ...base, reason: "invalid_assessment_timestamp" };
  try {
    const { manifest, data } = readPinnedDebianTrackerFullSnapshot(input.stateRoot, input.snapshotSha256);
    const age = (Date.parse(now) - Date.parse(manifest.capturedAt)) / 3_600_000;
    const evidence = {
      ...base, fullSnapshotSha256: manifest.sha256,
      importedAt: manifest.capturedAt, localImportAgeHours: Math.max(0, age),
    };
    if (age < -5 / 60) return { ...evidence, reason: "future_dated_local_snapshot" };
    if (age > maxAgeHours) return { ...evidence, reason: "local_import_window_expired" };
    if (!Object.hasOwn(data, input.sourcePackage) || !record(data[input.sourcePackage])) {
      return { ...evidence, reason: "source_package_not_listed" };
    }
    const source = data[input.sourcePackage] as JsonRecord;
    if (!Object.hasOwn(source, input.cveId)) return { ...evidence, reason: "cve_not_listed_unknown_not_clean" };
    const excerptRaw = JSON.stringify({ [input.sourcePackage]: { [input.cveId]: source[input.cveId] } });
    const excerptSha = sha256(excerptRaw);
    const excerpt = parseDebianTrackerExcerpt(excerptRaw, excerptSha);
    const evaluation = evaluateDebianTrackerExcerpt(excerpt, {
      osId: input.osId, inventoryComplete: input.inventoryComplete,
      sourcePackage: input.sourcePackage, sourceVersion: input.sourceVersion,
      cveId: input.cveId, release: input.release,
    });
    return {
      ...evidence, status: evaluation.status, reason: evaluation.reason,
      candidateVerdict: evaluation.candidateVerdict,
      derivedExcerptSha256: excerptSha, fixedVersion: evaluation.fixedVersion,
    };
  } catch {
    return { ...base, reason: "pinned_full_snapshot_or_derived_excerpt_invalid" };
  }
}
