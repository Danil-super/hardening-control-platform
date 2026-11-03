/**
 * Count actual Node fetch *decoded* response bytes without buffering or
 * publishing the mutable Debian tracker feed. This is a diagnostics-only
 * disposable CI check, NOT an import or data-source trust attestation.
 */
const endpoint = "https://security-tracker.debian.org/tracker/data/json";
const limit = 256 * 1024 * 1024;
const response = await fetch(endpoint, {
  method: "GET", redirect: "error", credentials: "omit", cache: "no-store",
  headers: { Accept: "application/json" }, signal: AbortSignal.timeout(90_000),
});
console.log(JSON.stringify({
  phase: "headers", status: response.status,
  contentType: response.headers.get("content-type"),
  contentLength: response.headers.get("content-length"),
  contentEncoding: response.headers.get("content-encoding"),
  transferEncoding: response.headers.get("transfer-encoding"),
  nodeFetchDecodedByteCap: limit,
}));
if (response.status !== 200 || !response.body) throw Error("Live feed unavailable");
const reader = response.body.getReader();
let total = 0;
try {
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) throw Error("Live feed exceeds diagnostic size bound");
  }
} catch (error) {
  await reader.cancel().catch(() => {});
  throw error;
} finally {
  reader.releaseLock();
}
console.log(JSON.stringify({ phase: "decoded-download-complete", decodedBytes: total }));
