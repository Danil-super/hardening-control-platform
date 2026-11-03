/**
 * HCP's bounded projection of a read-only APT cache integrity check.
 *
 * Positive state means only that cached decompressed Packages SHA-256 bytes
 * match a gpgv-verified cached InRelease signed by the host's OWN local keyring.
 * It is NOT external Debian publisher attestation, full repository coverage,
 * installed .deb provenance, or remediation authorization.
 */
export type DebianPackageIndexEvidence = {
  schemaVersion: 1;
  status: "locally_hash_matched" | "partial" | "unavailable" | "budget_exceeded" | "not_collected" | "invalid";
  releaseCodename: string | null;
  candidateIndexes: number;
  matchedIndexes: number;
  missingSignedHashes: number;
  mismatchedIndexes: number;
  indexRecords: Array<{
    suite: string; component: string; architecture: string;
    releaseSha256: string; packagesSha256: string; packagesBytes: number;
  }>;
  verifiedAgainstLocallySignedRelease: boolean;
  installedVersionCandidates?: {
    schemaVersion: 1;
    status: "candidate_record_match" | "no_exact_match" | "unavailable";
    eligibleInstalled: number;
    exactInstalledVersionCandidates: number;
    matchedIdentitySha256: string | null;
    scope: "installed-dpkg-version-in-locally-verified-Packages-record-v1";
    publisherAuthenticated: false;
    installedPackageOriginVerified: false;
    remediationAuthorized: false;
  };
  publisherAuthenticated: false;
  keyringIndependentlyAuthenticated: false;
  publisherFreshnessVerified: false;
  installedPackageOriginVerified: false;
  remediationAuthorized: false;
  provenanceScope: "cached-debian-packages-uncompressed-sha256-locally-signed-release-v1";
  note: string;
};

const SHA = /^[0-9a-f]{64}$/;
const SUITE = /^[a-z][a-z0-9-]{1,31}$/;
const COMPONENT = /^[a-z][a-z0-9-]{0,31}$/;
const ARCH = /^[a-z0-9]{2,20}$/;
const SCOPE = "cached-debian-packages-uncompressed-sha256-locally-signed-release-v1";
const MAX_BYTES = 160 * 1024 * 1024;
const CANDIDATE_SCOPE = "installed-dpkg-version-in-locally-verified-Packages-record-v1";
const note = "Сверены SHA-256 распакованных локальных индексов Packages с хешами в локальном InRelease, " +
  "подпись которого проверена по набору ключей самой проверяемой ОС. Набор ключей не аттестован независимо. " +
  "Не удостоверены издатель, полнота всех репозиториев, дата у издателя, архив .deb и происхождение установленных пакетов.";

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function empty(status: DebianPackageIndexEvidence["status"], codename: string | null): DebianPackageIndexEvidence {
  return {
    schemaVersion: 1, status, releaseCodename: codename,
    candidateIndexes: 0, matchedIndexes: 0, missingSignedHashes: 0, mismatchedIndexes: 0,
    indexRecords: [], verifiedAgainstLocallySignedRelease: false,
    publisherAuthenticated: false, keyringIndependentlyAuthenticated: false,
    publisherFreshnessVerified: false, installedPackageOriginVerified: false,
    remediationAuthorized: false, provenanceScope: SCOPE, note,
  };
}
export function summarizeDebianPackageIndexes(
  source: unknown, osRelease: Record<string, unknown>,
): DebianPackageIndexEvidence | null {
  if (osRelease.ID !== "debian") return null;
  const codename = typeof osRelease.VERSION_CODENAME === "string" && SUITE.test(osRelease.VERSION_CODENAME)
    ? osRelease.VERSION_CODENAME : null;
  if (source === undefined) return empty("not_collected", codename);
  const data = record(source);
  if (!data) return empty("invalid", codename);
  const status = String(data.status);
  const cnt = (key: string, max: number) => Number.isSafeInteger(data[key])
    && (data[key] as number) >= 0 && (data[key] as number) <= max;
  const records = data.indexRecords;
  if (data.schemaVersion !== 1
    || !["locally_hash_matched", "partial", "unavailable", "budget_exceeded"].includes(status)
    || data.releaseCodename !== codename || data.scope !== SCOPE
    || data.publisherAuthenticated !== false || data.keyringIndependentlyAuthenticated !== false
    || data.publisherFreshnessVerified !== false || data.installedPackageOriginVerified !== false
    || data.remediationAuthorized !== false
    || typeof data.verifiedAgainstLocallySignedRelease !== "boolean"
    || !cnt("candidateIndexes", 20000) || !cnt("matchedIndexes", 8)
    || !cnt("missingSignedHashes", 8) || !cnt("mismatchedIndexes", 8)
    || (data.matchedIndexes as number) + (data.missingSignedHashes as number)
      + (data.mismatchedIndexes as number) > (data.candidateIndexes as number)
    || !Array.isArray(records) || records.length !== data.matchedIndexes || records.length > 8
    || records.some(raw => {
      const item = record(raw);
      return !item || ![item.suite, item.component, item.architecture].every(x => typeof x === "string")
        || !SUITE.test(item.suite as string) || !COMPONENT.test(item.component as string)
        || !ARCH.test(item.architecture as string)
        || !SHA.test(String(item.releaseSha256)) || !SHA.test(String(item.packagesSha256))
        || !Number.isSafeInteger(item.packagesBytes) || (item.packagesBytes as number) < 1
        || (item.packagesBytes as number) > MAX_BYTES;
    })
    || (status === "locally_hash_matched") !== data.verifiedAgainstLocallySignedRelease
    || (status === "locally_hash_matched" && ((data.candidateIndexes as number) < 1
      || data.candidateIndexes !== data.matchedIndexes || data.missingSignedHashes !== 0 || data.mismatchedIndexes !== 0))
    || ((status === "unavailable" || status === "budget_exceeded")
      && ((data.matchedIndexes as number) !== 0 || records.length !== 0))
    || (codename && records.some(raw => {
      const suite = (raw as Record<string, unknown>).suite;
      return ![codename, codename + "-security", codename + "-updates", codename + "-backports"].includes(String(suite));
    }))
  ) return empty("invalid", codename);

  // Optional exact installed-version record matches must be tied to the
  // successful index hash gate. Neither a record match nor its SHA identifies
  // the installed .deb archive or grants remediation authority.
  let installedVersionCandidates: DebianPackageIndexEvidence["installedVersionCandidates"];
  if (Object.prototype.hasOwnProperty.call(data, "installedVersionCandidates")) {
    const candidate = record(data.installedVersionCandidates);
    const candidateStatus = candidate?.status;
    const eligible = candidate?.eligibleInstalled;
    const matches = candidate?.exactInstalledVersionCandidates;
    const digest = candidate?.matchedIdentitySha256;
    if (!candidate || candidate.schemaVersion !== 1
      || !["candidate_record_match", "no_exact_match", "unavailable"].includes(String(candidateStatus))
      || !Number.isSafeInteger(eligible) || (eligible as number) < 0 || (eligible as number) > 250000
      || !Number.isSafeInteger(matches) || (matches as number) < 0 || (matches as number) > (eligible as number)
      || candidate.scope !== CANDIDATE_SCOPE
      || candidate.publisherAuthenticated !== false || candidate.installedPackageOriginVerified !== false
      || candidate.remediationAuthorized !== false
      || (candidateStatus === "unavailable" && (matches !== 0 || digest !== null))
      || (candidateStatus === "candidate_record_match" && ((matches as number) < 1 || !SHA.test(String(digest))))
      || (candidateStatus === "no_exact_match" && (matches !== 0 || !SHA.test(String(digest))))
      || (candidateStatus !== "unavailable" && status !== "locally_hash_matched")
    ) return empty("invalid", codename);
    installedVersionCandidates = {
      schemaVersion: 1,
      status: candidateStatus as "candidate_record_match" | "no_exact_match" | "unavailable",
      eligibleInstalled: eligible as number,
      exactInstalledVersionCandidates: matches as number,
      matchedIdentitySha256: digest as string | null,
      scope: CANDIDATE_SCOPE,
      publisherAuthenticated: false,
      installedPackageOriginVerified: false,
      remediationAuthorized: false,
    };
  }

  // Recreate without untrusted keys/hidden metadata, preserve every eligible
  // signed index's exact count and SHA identity, including repeated suites.
  return {
    ...empty(status as DebianPackageIndexEvidence["status"], codename),
    candidateIndexes: data.candidateIndexes as number,
    matchedIndexes: data.matchedIndexes as number,
    missingSignedHashes: data.missingSignedHashes as number,
    mismatchedIndexes: data.mismatchedIndexes as number,
    indexRecords: (records as DebianPackageIndexEvidence["indexRecords"]).map(item => ({
      suite: item.suite, component: item.component, architecture: item.architecture,
      releaseSha256: item.releaseSha256, packagesSha256: item.packagesSha256, packagesBytes: item.packagesBytes,
    })),
    verifiedAgainstLocallySignedRelease: data.verifiedAgainstLocallySignedRelease as boolean,
    ...(installedVersionCandidates ? { installedVersionCandidates } : {}),
  };
}
