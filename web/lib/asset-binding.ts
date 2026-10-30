import { createHash, createHmac } from "node:crypto";

export type AssetObservation = { machineIdSha256: string; sshHostKeyFingerprint: string; observedAt: string };
export type VerifiedAssetBinding = {
  version: 1; status: "verified"; assetId: string; alias: string; generation: number;
  machineIdSha256: string; sshHostKeyFingerprint: string; verifiedAt: string;
  connectionId: string;
};
export type UnknownAssetBinding = {
  version: 1; status: "unknown"; alias: string; reason: "unauthenticated_network_scan";
  connectionId: string; aliasGeneration: number | null; observedAt: string;
};
export type AssetBinding = VerifiedAssetBinding | UnknownAssetBinding;
export const validAssetAlias = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}$/.test(value);
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const validHash = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const validTime = (value: unknown): value is string => typeof value === "string" && Number.isFinite(Date.parse(value));
export const validHostFingerprint = (value: unknown): value is string => typeof value === "string" && /^SHA256:[A-Za-z0-9+/]{43}=?$/.test(value);

/** Never persist or expose the raw machine-id (systemd treats it as confidential). */
export function machineIdentityHash(machineId: string) {
  if (!/^[a-f0-9]{32}$/.test(machineId) || /^0+$/.test(machineId)) throw new Error("Хост не предоставил корректный непустой machine-id (/etc/machine-id либо /var/lib/dbus/machine-id).");
  return createHmac("sha256", "hardening-control-platform/asset-identity/v1").update(machineId).digest("hex");
}

export function assetIdForObservation(value: AssetObservation) {
  if (!validHash(value.machineIdSha256) || !validHostFingerprint(value.sshHostKeyFingerprint) || !validTime(value.observedAt)) throw new Error("Неполное подтверждение идентичности актива.");
  return `asset-${hash(JSON.stringify([value.machineIdSha256, value.sshHostKeyFingerprint]))}`;
}

export function assetConnectionId(connection: { address: string; port: number; user?: string }) {
  return hash(JSON.stringify([connection.address.toLowerCase(), connection.port, connection.user ?? ""]));
}

export function parseAssetBinding(value: unknown): AssetBinding | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (row.version !== 1 || !validAssetAlias(row.alias) || !validHash(row.connectionId)) return null;
  if (row.status === "unknown" && row.reason === "unauthenticated_network_scan" && validTime(row.observedAt)
      && (row.aliasGeneration === null || Number.isSafeInteger(row.aliasGeneration) && Number(row.aliasGeneration) > 0)) return row as UnknownAssetBinding;
  if (row.status !== "verified" || !Number.isSafeInteger(row.generation) || Number(row.generation) < 1
      || !validHash(row.machineIdSha256) || !validHostFingerprint(row.sshHostKeyFingerprint) || !validTime(row.verifiedAt)) return null;
  const assetId = assetIdForObservation({ machineIdSha256: row.machineIdSha256, sshHostKeyFingerprint: row.sshHostKeyFingerprint, observedAt: row.verifiedAt });
  return row.assetId === assetId ? row as VerifiedAssetBinding : null;
}

/** Legacy evidence is never silently assigned the current identity of an alias. */
export function assetEvidenceKey(binding: AssetBinding | null | undefined) {
  if (!binding) return "legacy";
  return binding.status === "verified" ? binding.assetId
    : `unknown:${binding.alias}:${binding.aliasGeneration ?? 0}:${binding.connectionId}`;
}

export function sameAssetEvidence(left: AssetBinding | null | undefined, right: AssetBinding | null | undefined) {
  return assetEvidenceKey(left) === assetEvidenceKey(right);
}
