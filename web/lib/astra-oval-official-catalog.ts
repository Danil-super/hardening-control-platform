/**
 * Untrusted vendor-repository metadata preview on the HCP controller.
 * URL choices are fixed in source; browser input cannot choose a URL, domain
 * or path. A repository SHA over HTTPS is NOT an independent publisher
 * signature or operator approval.
 */
type Release = "1.7" | "1.8";
const sources: Record<Release, { url: string; metadataUrl: string }> = {
  "1.7": {
    url: "https://dl.astralinux.ru/artifactory/al-oval/1.7_x86-64/oval-definitions-alse-1.7.xml",
    metadataUrl: "https://dl.astralinux.ru/artifactory/api/storage/al-oval/1.7_x86-64/oval-definitions-alse-1.7.xml",
  },
  "1.8": {
    url: "https://dl.astralinux.ru/artifactory/al-oval/1.8_x86-64/oval-definitions-alse-1.8.xml",
    metadataUrl: "https://dl.astralinux.ru/artifactory/api/storage/al-oval/1.8_x86-64/oval-definitions-alse-1.8.xml",
  },
};
const MAX_METADATA_BYTES = 65536;
const MAX_XML_BYTES = 192 * 1024 * 1024;
const DIGEST = /^[a-f0-9]{64}$/;

export type AstraOvalCatalogPreview = {
  release: Release;
  url: string;
  metadataUrl: string;
  sha256: string;
  bytes: number;
  observedAt: string;
  sourceName: string;
  sourceReference: string;
  sourceReviewedAt: null;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
  warning: string;
};

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

async function boundedJson(response: Response): Promise<unknown> {
  if (!response.ok || !response.body) throw new Error("Official Astra metadata endpoint unavailable");
  const length = response.headers.get("content-length");
  if (length && (!/^\d{1,7}$/.test(length) || Number(length) > MAX_METADATA_BYTES)) {
    throw new Error("Vendor metadata exceeds safe response budget");
  }
  const reader = response.body.getReader();
  let bytes = 0;
  const parts: Uint8Array[] = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_METADATA_BYTES) throw new Error("Vendor metadata exceeded response budget");
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (bytes < 2) throw new Error("Empty vendor metadata");
  try {
    return JSON.parse(Buffer.concat(parts.map(part => Buffer.from(part))).toString("utf8"));
  } catch {
    throw new Error("Invalid vendor metadata JSON");
  }
}

/** No additional hostname/URL/redirect is accepted from callers or metadata. */
export async function readOfficialAstraOvalCatalog(
  release: string, fetcher: typeof fetch = fetch,
): Promise<AstraOvalCatalogPreview> {
  if (release !== "1.7" && release !== "1.8") {
    throw new Error("Only the fixed Astra OVAL 1.7/1.8 catalog entries are supported");
  }
  const selected = sources[release];
  const response = await fetcher(selected.metadataUrl, {
    method: "GET",
    redirect: "error",
    cache: "no-store",
    credentials: "omit",
    signal: AbortSignal.timeout(10000),
    headers: { Accept: "application/json" },
  });
  const raw = record(await boundedJson(response));
  const checksums = record(raw?.checksums);
  const rawSha = checksums?.sha256;
  const sha256 = typeof rawSha === "string" ? rawSha.toLowerCase() : "";
  const size = raw?.size;
  const sizeValue = typeof size === "number" ? size
    : typeof size === "string" && /^\d{1,12}$/.test(size) ? Number(size) : NaN;
  if (!DIGEST.test(sha256) || !Number.isSafeInteger(sizeValue)
    || sizeValue < 1024 || sizeValue > MAX_XML_BYTES) {
    throw new Error("Official Astra repository did not provide bounded SHA-256 and size");
  }
  return {
    release, ...selected, sha256, bytes: sizeValue,
    observedAt: new Date().toISOString(),
    sourceName: "Каталог Astra Linux OVAL " + release,
    sourceReference: selected.metadataUrl,
    sourceReviewedAt: null,
    publisherAuthenticated: false, publisherFreshnessVerified: false,
    remediationAuthorized: false,
    warning: "SHA-256 наблюдался в том же HTTPS-хранилище. Это не независимая подпись производителя, " +
      "не подтверждение применимости выпуска и не разрешение на исправление. " +
      "Администратор должен отдельно проверить официальный бюллетень и выбранный выпуск.",
  };
}
