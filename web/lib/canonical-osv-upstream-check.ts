import { createHash } from "node:crypto";
import { readPinnedAdvisorySnapshot, canonicalUbuntuOsvReference, ADVISORY_SNAPSHOT_MAX_BYTES } from "@/lib/vendor-advisory-snapshot";
import { parseUbuntuOsvSnapshot } from "@/lib/ubuntu-osv-crosscheck";

/**
 * Read-only, operator-invoked *observation* of GitHub's public branch and an
 * exact CVE file. This is neither a trusted Canonical signature verification
 * nor a guarantee that the observed branch tip remains current.
 *
 * Not used by audit jobs, schedulers, report rendering, or remediation.
 */
export type CanonicalOsvUpstreamObservation = {
  schemaVersion: 1;
  status: "same_content_at_observed_head" | "changed_content_at_observed_head"
    | "missing_at_observed_head" | "unavailable";
  reason: string;
  recordId: string | null;
  observedAt: string;
  pinnedRevision: string | null;
  observedHeadRevision: string | null;
  localSha256: string | null;
  observedSha256: string | null;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  trustedVerdict: "unknown";
  remediationAuthorized: false;
  source: "github-https-branch-observation";
};

const HEAD_API = "https://api.github.com/repos/canonical/ubuntu-security-notices/branches/main";
const SHA40 = /^[a-f0-9]{40}$/;
const SHA64 = /^[a-f0-9]{64}$/;
const HEAD_LIMIT = 32 * 1024;
const FETCH_TIMEOUT = 20_000;

function unavailable(reason: string, observedAt: string, local?: {
  recordId: string; pinnedRevision: string; localSha256: string;
}): CanonicalOsvUpstreamObservation {
  return {
    schemaVersion: 1, status: "unavailable", reason, observedAt,
    recordId: local?.recordId ?? null, pinnedRevision: local?.pinnedRevision ?? null,
    localSha256: local?.localSha256 ?? null, observedHeadRevision: null, observedSha256: null,
    publisherAuthenticated: false, publisherFreshnessVerified: false,
    trustedVerdict: "unknown", remediationAuthorized: false,
    source: "github-https-branch-observation",
  };
}

async function readBounded(response: Response, expectedUrl: string, limit: number, mimeTypes: readonly string[]): Promise<Buffer> {
  if (response.status !== 200 || !response.ok || response.redirected
    || (response.url && response.url !== expectedUrl)) throw new Error("upstream_http_status_or_redirect");
  const type = (response.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (!mimeTypes.includes(type)) throw new Error("upstream_content_type");
  const announced = response.headers.get("content-length");
  if (announced !== null && (!/^\d+$/.test(announced) || !Number.isSafeInteger(Number(announced))
    || Number(announced) < 1 || Number(announced) > limit)) throw new Error("upstream_announced_size");
  if (!response.body) throw new Error("upstream_empty_response");
  const reader = response.body.getReader();
  let length = 0;
  const chunks: Buffer[] = [];
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > limit) throw new Error("upstream_stream_exceeds_limit");
      chunks.push(Buffer.from(part.value));
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  if (!length) throw new Error("upstream_empty_response");
  return Buffer.concat(chunks, length);
}

async function getFixedUrl(transport: typeof fetch, url: string, limit: number, types: readonly string[]) {
  const response = await transport(url, {
    method: "GET", redirect: "error", cache: "no-store", credentials: "omit",
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
    headers: { Accept: "application/vnd.github+json, application/json, text/plain;q=0.9" },
  });
  if (response.status === 404 && !response.redirected && (!response.url || response.url === url)) {
    return null;
  }
  return readBounded(response, url, limit, types);
}

/** Compare an immutable local CVE file against the same file at an observed HEAD. */
export async function inspectCanonicalOsvUpstream(input: {
  stateRoot: string;
  snapshotSha256: string;
  fetchImpl?: typeof fetch;
  now?: string;
}): Promise<CanonicalOsvUpstreamObservation> {
  const now = input.now ?? new Date().toISOString();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(now)
      || !Number.isFinite(Date.parse(now))) throw new Error("Invalid observation time");
  if (!SHA64.test(input.snapshotSha256)) return unavailable("invalid_local_digest", now);
  let local: { recordId: string; pinnedRevision: string; localSha256: string };
  try {
    const snapshot = readPinnedAdvisorySnapshot(input.stateRoot, input.snapshotSha256);
    if (!snapshot.manifest.sourceReference || snapshot.manifest.sourceReference.kind !== "canonical-github-pinned-revision") {
      return unavailable("local_snapshot_has_no_pinned_canonical_origin", now);
    }
    local = {
      recordId: snapshot.manifest.recordId,
      pinnedRevision: snapshot.manifest.sourceReference.revision,
      localSha256: snapshot.manifest.sha256,
    };
    // Reuse the strict parser before contacting the remote endpoint.
    parseUbuntuOsvSnapshot(snapshot.rawJson, snapshot.manifest.sha256);
  } catch {
    return unavailable("local_snapshot_missing_or_invalid", now);
  }
  const transport = input.fetchImpl ?? fetch;
  try {
    const rawHead = await getFixedUrl(transport, HEAD_API, HEAD_LIMIT, ["application/json", "application/vnd.github+json"]);
    if (!rawHead) return unavailable("github_branch_unavailable", now, local);
    const branch: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawHead));
    if (!branch || typeof branch !== "object" || Array.isArray(branch)) {
      return unavailable("github_branch_schema_invalid", now, local);
    }
    const b = branch as { name?: unknown; commit?: { sha?: unknown } };
    const headSha = b.commit?.sha;
    if (b.name !== "main" || typeof headSha !== "string" || !SHA40.test(headSha)) {
      return unavailable("github_branch_schema_invalid", now, local);
    }
    const ref = canonicalUbuntuOsvReference(local.recordId, headSha);
    const data = await getFixedUrl(transport, ref.url, ADVISORY_SNAPSHOT_MAX_BYTES,
      ["application/json", "text/plain", "application/octet-stream"]);
    const base = {
      schemaVersion: 1 as const, recordId: local.recordId, observedAt: now,
      pinnedRevision: local.pinnedRevision, observedHeadRevision: headSha,
      localSha256: local.localSha256, publisherAuthenticated: false as const,
      publisherFreshnessVerified: false as const, trustedVerdict: "unknown" as const,
      remediationAuthorized: false as const, source: "github-https-branch-observation" as const,
    };
    if (!data) return { ...base, status: "missing_at_observed_head", reason: "canonical_cve_missing_at_observed_revision", observedSha256: null };
    const observedSha256 = createHash("sha256").update(data).digest("hex");
    const json = new TextDecoder("utf-8", { fatal: true }).decode(data);
    const parsed = parseUbuntuOsvSnapshot(json, observedSha256);
    if (parsed.record.id !== local.recordId) return {
      ...base, status: "unavailable", reason: "upstream_cve_identity_changed", observedSha256: null,
    };
    const same = observedSha256 === local.localSha256;
    return {
      ...base,
      status: same ? "same_content_at_observed_head" : "changed_content_at_observed_head",
      reason: same ? "cve_bytes_match_at_observed_revision" : "cve_bytes_differ_at_observed_revision",
      observedSha256,
    };
  } catch {
    // Network outages, API errors, HTML and malformed data cannot turn into
    // a "same"/"current" verdict. Never propagate untrusted HTTP text.
    return unavailable("github_observation_failed_or_invalid", now, local);
  }
}
