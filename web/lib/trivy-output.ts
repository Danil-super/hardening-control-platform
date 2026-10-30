import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, type BigIntStats } from "node:fs";

// Match hcp-trivy-source.py; the native acceptance replay uses the same budget.
export const TRIVY_STDOUT_LIMIT = 64 * 1024 * 1024;
export type TrivyStdoutFileEvidence = { sha256: string; bytes: number };

function sameFile(left: BigIntStats, right: BigIntStats) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs && left.nlink === right.nlink;
}

/** Read only the private path created for this run, bounded even if it grows. */
export function readTrivyOutputFile(file: string, evidence: TrivyStdoutFileEvidence | undefined): string {
  if (!evidence || !Number.isSafeInteger(evidence.bytes) || evidence.bytes < 0 || evidence.bytes > TRIVY_STDOUT_LIMIT
      || typeof evidence.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(evidence.sha256)) {
    throw new Error("Trivy output lacks bounded size and digest evidence");
  }
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== BigInt(1) || (before.mode & BigInt(0o077)) !== BigInt(0)
        || before.size !== BigInt(evidence.bytes)) {
      throw new Error("Trivy output is not the expected private ordinary file");
    }
    // One extra byte detects growth without reading an unbounded changing file.
    const buffer = Buffer.alloc(evidence.bytes + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const count = readSync(fd, buffer, bytes, Math.min(64 * 1024, buffer.length - bytes), null);
      if (!count) break;
      bytes += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(file, { bigint: true });
    if (bytes !== evidence.bytes || !current.isFile() || !sameFile(before, after) || !sameFile(after, current)
        || createHash("sha256").update(buffer.subarray(0, bytes)).digest("hex") !== evidence.sha256) {
      throw new Error("Trivy output changed, was replaced or did not finish writing");
    }
    // Preserve native bytes. Invalid UTF-8 is an error, not replacement text.
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytes));
  } finally { closeSync(fd); }
}
