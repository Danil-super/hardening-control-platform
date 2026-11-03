/**
 * Read-only, host-scoped projection of a gpgv result against a LOCAL Debian
 * archive keyring. This is distinct from publisher authentication and from
 * provenance of any installed binary/package archive.
 */
export type DebianSignedReleaseObservation = {
  schemaVersion: 1;
  status: "verified_with_local_keyring" | "partial" | "unavailable" | "not_collected" | "invalid";
  releaseCodename: string | null;
  candidateFiles: number;
  validLocalSignatures: number;
  invalidOrUnverifiable: number;
  signedReleases: string[];
  signerFingerprints: string[];
  inReleaseSha256: string[];
  localKeyringSha256: string | null;
  localSignatureVerified: boolean;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  packageIndexHashesVerified: false;
  installedPackageOriginVerified: false;
  remediationAuthorized: false;
  provenanceScope: "cached-inrelease-gpgv-installed-archive-keyring-only";
  note: string;
};
const SHA = /^[a-f0-9]{64}$/;
const FINGERPRINT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const RELEASE = /^[a-z][a-z0-9-]{1,31}$/;
const scope = "cached-inrelease-gpgv-installed-archive-keyring-only";
const note = "Подпись локального InRelease проверялась gpgv с установленным на хосте набором ключей Debian. " +
  "Подлинность самого набора ключей из независимого источника не установлена. " +
  "Хеши Packages, подлинность установленного .deb, актуальность издателя и разрешение исправлений не подтверждены.";

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function base(state: DebianSignedReleaseObservation["status"], codename: string | null): DebianSignedReleaseObservation {
  return { schemaVersion: 1, status: state, releaseCodename: codename,
    candidateFiles: 0, validLocalSignatures: 0, invalidOrUnverifiable: 0,
    signedReleases: [], signerFingerprints: [], inReleaseSha256: [],
    localKeyringSha256: null, localSignatureVerified: false,
    publisherAuthenticated: false, publisherFreshnessVerified: false,
    packageIndexHashesVerified: false, installedPackageOriginVerified: false,
    remediationAuthorized: false, provenanceScope: scope, note,
  };
}

/** A malformed, spoofed or future-version claim becomes invalid, never signed. */
export function summarizeDebianSignedReleases(raw: unknown, osRelease: Record<string, unknown>): DebianSignedReleaseObservation | null {
  if (osRelease.ID !== "debian") return null;
  const codename = typeof osRelease.VERSION_CODENAME === "string" && RELEASE.test(osRelease.VERSION_CODENAME)
    ? osRelease.VERSION_CODENAME : null;
  if (raw === undefined) return base("not_collected", codename);
  const item = record(raw);
  if (!item) return base("invalid", codename);
  const status = item.status;
  const n = (key: string, max: number) => Number.isSafeInteger(item[key]) && (item[key] as number) >= 0 && (item[key] as number) <= max;
  const arr = (key: string, max: number, re: RegExp) =>
    Array.isArray(item[key]) && (item[key] as unknown[]).length <= max
      && (item[key] as unknown[]).every(x => typeof x === "string" && re.test(x));
  if (item.schemaVersion !== 1 || !["verified_with_local_keyring", "partial", "unavailable"].includes(String(status))
    || item.releaseCodename !== codename
    || item.scope !== scope
    || !n("candidateFiles", 12) || !n("validLocalSignatures", 12) || !n("invalidOrUnverifiable", 12)
    || !arr("signedReleases", 4, RELEASE)
    || !arr("inReleaseSha256", 12, SHA)
    || !arr("signerFingerprints", 16, FINGERPRINT)
    || !(item.localKeyringSha256 === null || (typeof item.localKeyringSha256 === "string" && SHA.test(item.localKeyringSha256)))
    || typeof item.localSignatureVerified !== "boolean"
    || item.publisherAuthenticated !== false || item.publisherFreshnessVerified !== false
    || item.packageIndexHashesVerified !== false || item.installedPackageOriginVerified !== false
    || item.remediationAuthorized !== false
    || (item.validLocalSignatures as number) + (item.invalidOrUnverifiable as number) > (item.candidateFiles as number)
    || (item.inReleaseSha256 as unknown[]).length !== item.validLocalSignatures
    || ((item.validLocalSignatures as number) > 0 && (
      !(item.signerFingerprints as unknown[]).length || !(item.signedReleases as unknown[]).length || !item.localKeyringSha256))
    || ((status === "verified_with_local_keyring") !== item.localSignatureVerified)
    || (status === "verified_with_local_keyring" && (
      (item.candidateFiles as number) === 0 || item.validLocalSignatures !== item.candidateFiles ||
      item.invalidOrUnverifiable !== 0))
    || (status === "unavailable" && item.localSignatureVerified !== false)
  ) return base("invalid", codename);
  const allowed = new Set([codename, codename && codename + "-security", codename && codename + "-updates",
    codename && codename + "-backports"]);
  if ((item.signedReleases as string[]).some(value => !allowed.has(value))) return base("invalid", codename);
  return {
    ...base(status as DebianSignedReleaseObservation["status"], codename),
    candidateFiles: item.candidateFiles as number,
    validLocalSignatures: item.validLocalSignatures as number,
    invalidOrUnverifiable: item.invalidOrUnverifiable as number,
    signedReleases: item.signedReleases as string[],
    signerFingerprints: item.signerFingerprints as string[],
    inReleaseSha256: item.inReleaseSha256 as string[],
    localKeyringSha256: item.localKeyringSha256 as string | null,
    localSignatureVerified: item.localSignatureVerified as boolean,
  };
}
