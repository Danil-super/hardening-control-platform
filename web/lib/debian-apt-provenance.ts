/**
 * Controller-only, strictly bounded projection of read-only apt-cache policy
 * from the native package inventory. APT's repository index metadata can
 * suggest configured suites; it does NOT establish where installed .deb bytes
 * came from or that an InRelease signature was verified.
 */
export type DebianAptRepositoryEvidence = {
  schemaVersion: 1;
  state: "observed" | "ambiguous" | "unavailable" | "not_collected" | "invalid";
  releaseCodename: string | null;
  indexEntries: number;
  debianLabelEntries: number;
  otherLabelEntries: number;
  suites: string[];
  policySha256: string | null;
  suiteConsistent: boolean;
  publisherAuthenticated: false;
  repositorySignatureVerified: false;
  installedPackageOriginVerified: false;
  provenanceScope: "configured-apt-indexes-only";
  note: string;
};

const SHA = /^[a-f0-9]{64}$/;
const SUITE = /^[a-z][a-z0-9-]{1,31}$/;
const note = "APT показывает метаданные настроенных индексов, но это не подтверждение цифровой подписи " +
  "репозитория, происхождения установленных .deb или применимости CVE к конкретному пакету. " +
  "Совпадение названия выпуска не доказывает подлинность источника; Trivy и исправления не меняются.";
const scope = "apt-cache-policy-index-metadata-only; no-installed-origin-or-signature-attestation";

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function base(state: DebianAptRepositoryEvidence["state"], codename: string | null): DebianAptRepositoryEvidence {
  return {
    schemaVersion: 1, state, releaseCodename: codename,
    indexEntries: 0, debianLabelEntries: 0, otherLabelEntries: 0,
    suites: [], policySha256: null, suiteConsistent: false,
    publisherAuthenticated: false, repositorySignatureVerified: false,
    installedPackageOriginVerified: false, provenanceScope: "configured-apt-indexes-only", note,
  };
}
/**
 * Never trust source booleans or raw release labels, and never promote apt
 * metadata to individual CVE or package trustedVerdict.
 */
export function summarizeDebianAptRepositoryEvidence(
  value: unknown,
  osRelease: Record<string, string>,
): DebianAptRepositoryEvidence | null {
  if (osRelease.ID !== "debian") return null;
  const codename = typeof osRelease.VERSION_CODENAME === "string" && SUITE.test(osRelease.VERSION_CODENAME)
    ? osRelease.VERSION_CODENAME : null;
  if (value === undefined) return base("not_collected", codename);
  const entry = asRecord(value);
  if (!entry) return base("invalid", codename);
  const status = entry.status;
  if (!["observed", "ambiguous", "unavailable"].includes(String(status))
    || entry.schemaVersion !== 1
    || entry.releaseCodename !== codename
    || entry.publisherAuthenticated !== false
    || entry.repositorySignatureVerified !== false
    || entry.installedPackageOriginVerified !== false
    || entry.scope !== scope
    || !Number.isSafeInteger(entry.indexEntries) || (entry.indexEntries as number) < 0 || (entry.indexEntries as number) > 1024
    || !Number.isSafeInteger(entry.debianLabelEntries) || (entry.debianLabelEntries as number) < 0
    || !Number.isSafeInteger(entry.otherLabelEntries) || (entry.otherLabelEntries as number) < 0
    || !Number.isSafeInteger(entry.unknownLabelEntries) || (entry.unknownLabelEntries as number) < 0
    || !Array.isArray(entry.suites) || entry.suites.length > 32
    || entry.suites.some(x => typeof x !== "string" || !SUITE.test(x))
    || !Array.isArray(entry.releaseLabels) || entry.releaseLabels.length > 2
    || entry.releaseLabels.some(x => x !== "Debian" && x !== "other-label-observed")
    || typeof entry.suiteConsistent !== "boolean"
    || (entry.policySha256 !== null && (typeof entry.policySha256 !== "string" || !SHA.test(entry.policySha256)))
    || (status === "observed" && ((entry.indexEntries as number) < 1 || !entry.policySha256))
    || (status !== "observed" && ((entry.indexEntries as number) !== 0 || entry.suiteConsistent === true))
    || (entry.debianLabelEntries as number) + (entry.otherLabelEntries as number)
      + (entry.unknownLabelEntries as number) !== (entry.indexEntries as number)
  ) return base("invalid", codename);

  return {
    ...base(status as DebianAptRepositoryEvidence["state"], codename),
    indexEntries: entry.indexEntries as number,
    debianLabelEntries: entry.debianLabelEntries as number,
    otherLabelEntries: entry.otherLabelEntries as number,
    suites: entry.suites as string[],
    policySha256: entry.policySha256 as string | null,
    suiteConsistent: entry.suiteConsistent as boolean,
  };
}
