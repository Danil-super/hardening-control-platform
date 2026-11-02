import { createHash, randomUUID } from "node:crypto";
import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, linkSync, lstatSync,
  mkdirSync, openSync, readSync, rmSync, writeFileSync,
} from "node:fs";
import path from "node:path";

/**
 * Local immutable byte vault. A matching operator-provided digest is NOT
 * publisher authentication. No network I/O or host remediation occurs here.
 */
export const ADVISORY_SNAPSHOT_MAX_BYTES = 8 * 1024 * 1024;
const SHA = /^[a-f0-9]{64}$/;
const CVE = /^UBUNTU-CVE-\d{4}-\d{4,}$/;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;

export type AdvisorySnapshotManifest = {
  schemaVersion: 1;
  source: "ubuntu-osv-cve";
  recordId: string;
  sha256: string;
  bytes: number;
  importedAt: string;
  importMethod: "operator-pinned-local-sha256";
  publisherAuthenticated: false;
};

function rootDirectory(root: string): string {
  // The caller supplies an internal HCP state path, never user-provided URLs.
  // Final path components must be directories, not symlinks.
  const directory = path.join(root, "vendor-advisory-snapshots", "v1");
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  // HCP state root may be 0755 on an existing installation; the new
  // child directories must be private regardless of the root mode.
  const rootInfo = lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("Invalid HCP state root");
  for (const name of [path.join(root, "vendor-advisory-snapshots"), directory]) {
    const st = lstatSync(name);
    if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o077) !== 0) {
      throw new Error("Advisory state directory is not private or is a symbolic link");
    }
  }
  return directory;
}

function syncDirectory(directory: string) {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function readPrivateFile(filename: string, limit: number): Buffer {
  const fd = openSync(filename, constants.O_RDONLY | O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n
      || before.size <= 0n || before.size > BigInt(limit)) {
      throw new Error("Advisory snapshot file has invalid type, permissions or size");
    }
    const bytes = Number(before.size);
    const output = Buffer.alloc(bytes + 1);
    let count = 0;
    while (count < output.length) {
      const chunk = readSync(fd, output, count, Math.min(64 * 1024, output.length - count), null);
      if (!chunk) break;
      count += chunk;
    }
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(filename, { bigint: true });
    for (const property of ["dev", "ino", "size", "mtimeNs", "ctimeNs", "nlink"] as const) {
      if (before[property] !== after[property] || after[property] !== current[property]) {
        throw new Error("Advisory snapshot changed while reading");
      }
    }
    if (!current.isFile() || count !== bytes) throw new Error("Advisory snapshot changed size");
    return output.subarray(0, bytes);
  } finally { closeSync(fd); }
}

function atomicCreate(directory: string, finalPath: string, content: Buffer): void {
  const temporary = path.join(directory, `.advisory-${randomUUID()}.tmp`);
  try {
    const fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | O_NOFOLLOW, 0o600);
    try {
      fchmodSync(fd, 0o600);
      writeFileSync(fd, content);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    // Hard link publishes atomically and refuses replacement of an existing
    // immutable snapshot. The matching SHA is checked again by the reader.
    try { linkSync(temporary, finalPath); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    syncDirectory(directory);
  } finally { rmSync(temporary, { force: true }); }
}

function pathsFor(root: string, sha256: string) {
  if (!SHA.test(sha256)) throw new Error("Invalid advisory snapshot SHA-256");
  const dir = rootDirectory(root);
  return {
    dir,
    data: path.join(dir, `${sha256}.json`),
    manifest: path.join(dir, `${sha256}.manifest.json`),
  };
}

export function readPinnedAdvisorySnapshot(root: string, sha256: string): {
  manifest: AdvisorySnapshotManifest;
  rawJson: string;
} {
  const file = pathsFor(root, sha256);
  const rawManifest = readPrivateFile(file.manifest, 4096);
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawManifest));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid advisory manifest");
  const manifest = value as AdvisorySnapshotManifest;
  if (manifest.schemaVersion !== 1 || manifest.source !== "ubuntu-osv-cve" || !CVE.test(manifest.recordId)
    || manifest.sha256 !== sha256 || !Number.isSafeInteger(manifest.bytes) || manifest.bytes < 1
    || manifest.bytes > ADVISORY_SNAPSHOT_MAX_BYTES
    || manifest.publisherAuthenticated !== false || manifest.importMethod !== "operator-pinned-local-sha256"
    || typeof manifest.importedAt !== "string" || !Number.isFinite(Date.parse(manifest.importedAt))) {
    throw new Error("Invalid or inconsistent advisory manifest");
  }
  const bytes = readPrivateFile(file.data, ADVISORY_SNAPSHOT_MAX_BYTES);
  if (bytes.length !== manifest.bytes || createHash("sha256").update(bytes).digest("hex") !== sha256) {
    throw new Error("Advisory snapshot checksum differs from pinned import");
  }
  const rawJson = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const parsed: unknown = JSON.parse(rawJson);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
    || (parsed as Record<string, unknown>).id !== manifest.recordId) {
    throw new Error("Advisory record identifier differs from pinned manifest");
  }
  return { manifest, rawJson };
}

export function importPinnedUbuntuOsvSnapshot(input: {
  root: string;
  rawJson: string;
  expectedSha256: string;
  recordId: string;
}): AdvisorySnapshotManifest {
  if (!CVE.test(input.recordId) || !SHA.test(input.expectedSha256)) {
    throw new Error("Invalid Ubuntu CVE record or digest");
  }
  const bytes = Buffer.from(input.rawJson, "utf8");
  if (!bytes.length || bytes.length > ADVISORY_SNAPSHOT_MAX_BYTES
    || createHash("sha256").update(bytes).digest("hex") !== input.expectedSha256) {
    throw new Error("Local advisory bytes differ from the independently provided digest");
  }
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
    || (parsed as Record<string, unknown>).id !== input.recordId) {
    throw new Error("Local advisory CVE identifier does not match expected record");
  }
  const file = pathsFor(input.root, input.expectedSha256);
  atomicCreate(file.dir, file.data, bytes);
  const manifest: AdvisorySnapshotManifest = {
    schemaVersion: 1, source: "ubuntu-osv-cve", recordId: input.recordId,
    sha256: input.expectedSha256, bytes: bytes.length, importedAt: new Date().toISOString(),
    importMethod: "operator-pinned-local-sha256", publisherAuthenticated: false,
  };
  atomicCreate(file.dir, file.manifest, Buffer.from(JSON.stringify(manifest), "utf8"));
  const observed = readPinnedAdvisorySnapshot(input.root, input.expectedSha256);
  if (observed.manifest.recordId !== input.recordId || observed.rawJson !== input.rawJson) {
    throw new Error("Existing immutable advisory snapshot does not match this import");
  }
  return observed.manifest;
}
