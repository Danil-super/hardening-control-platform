import { createHash } from "node:crypto";
import {
  canonicalUbuntuOsvReference, importPinnedUbuntuOsvSnapshot,
  ADVISORY_SNAPSHOT_MAX_BYTES,
  type AdvisorySnapshotManifest, type CanonicalUbuntuOsvReference,
} from "@/lib/vendor-advisory-snapshot";
import { parseUbuntuOsvSnapshot } from "@/lib/ubuntu-osv-crosscheck";

const TIMEOUT_MS = 20_000;

/**
 * No arbitrary URL input. Fetch only a caller-pinned Git commit in Canonical's
 * public OSV GitHub repository and require a separately pinned file SHA-256.
 *
 * HTTPS transport validates the remote endpoint through the runtime CA store,
 * but does NOT constitute a signed vendor advisory or a publisher attestation.
 */
export type CanonicalOsvImportReceipt = {
  schemaVersion: 1;
  sourceReference: CanonicalUbuntuOsvReference;
  fileSha256: string;
  bytes: number;
  snapshot: AdvisorySnapshotManifest;
  publisherAuthenticated: false;
  transport: "fixed-https-origin-revision-pinned";
};

export async function fetchPinnedCanonicalUbuntuOsv(input: {
  stateRoot: string;
  recordId: string;
  revision: string;
  expectedSha256: string;
  /** Only inject for deterministic, network-free transport tests. */
  fetchImpl?: typeof fetch;
}): Promise<CanonicalOsvImportReceipt> {
  const ref = canonicalUbuntuOsvReference(input.recordId, input.revision);
  if (!/^[a-f0-9]{64}$/.test(input.expectedSha256)) {
    throw new Error("Expected independent SHA-256 pin is missing or invalid");
  }

  const transport = input.fetchImpl ?? fetch;
  // Fetch defaults may automatically follow redirects, including cross-origin.
  // Reject redirects, do not allow credentials, and bound the entire operation.
  const response = await transport(ref.url, {
    method: "GET", redirect: "error", cache: "no-store", credentials: "omit",
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { Accept: "application/json, text/plain;q=0.9" },
  });
  if (response.status !== 200 || !response.ok || response.redirected
      || (response.url && response.url !== ref.url)) {
    throw new Error("Canonical pinned snapshot request was redirected or rejected");
  }
  const contentType = (response.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (!["application/json", "text/plain", "application/octet-stream"].includes(contentType)) {
    throw new Error("Canonical snapshot HTTP content type is unsupported");
  }
  const announced = response.headers.get("content-length");
  if (announced !== null && (!/^\d+$/.test(announced) || !Number.isSafeInteger(Number(announced))
      || Number(announced) < 1 || Number(announced) > ADVISORY_SNAPSHOT_MAX_BYTES)) {
    throw new Error("Canonical snapshot HTTP size is invalid");
  }
  if (!response.body) throw new Error("Canonical snapshot response has no body");

  const reader = response.body.getReader();
  const parts: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      const value = next.value;
      total += value.byteLength;
      if (total > ADVISORY_SNAPSHOT_MAX_BYTES) {
        throw new Error("Canonical snapshot exceeded the bounded body limit");
      }
      parts.push(Buffer.from(value));
    }
  } finally {
    // No background network activity after the consumer has stopped reading.
    await reader.cancel().catch(() => {});
  }
  if (total < 1) throw new Error("Canonical OSV response is empty");
  // Validate actual bytes, not an untrusted Content-Length or advertised ETag.
  const buffer = Buffer.concat(parts, total);
  const actualSha256 = createHash("sha256").update(buffer).digest("hex");
  if (actualSha256 !== input.expectedSha256) {
    throw new Error("Canonical OSV response does not match the independently pinned SHA-256");
  }
  const rawJson = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  const snapshot = parseUbuntuOsvSnapshot(rawJson, input.expectedSha256);
  if (snapshot.record.id !== input.recordId) {
    throw new Error("Canonical OSV record identity differs from requested CVE");
  }

  // The vault accepts and retains the immutable origin claim. That claim is
  // NOT upgraded into a publisher signature/trust verdict.
  const manifest = importPinnedUbuntuOsvSnapshot({
    root: input.stateRoot, recordId: input.recordId, rawJson,
    expectedSha256: input.expectedSha256, sourceReference: ref,
  });
  return {
    schemaVersion: 1, sourceReference: ref, fileSha256: actualSha256,
    bytes: total, snapshot: manifest, publisherAuthenticated: false,
    transport: "fixed-https-origin-revision-pinned",
  };
}
