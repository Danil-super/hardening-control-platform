import { assetConnectionId, assetIdForObservation, type AssetBinding, type VerifiedAssetBinding } from "@/lib/asset-binding";
import { connectionPrivateKey } from "@/lib/host-credentials";
import { probeTrustedAssetIdentity, type TrustedAssetObservation } from "@/lib/ssh-access";
import { currentAssetBinding, recordAssetObservation } from "@/lib/state-store";

export type AssetConnection = { address: string; port: number; user?: string; credentialId?: string; privateKeyPath?: string; transport?: string };

export function assetPrivateKey(alias: string, connection: AssetConnection) {
  if (!connection.user) throw new Error("Для проверки идентичности укажите явный ansible_user в inventory.");
  if (connection.transport && connection.transport !== "ssh") throw new Error("Проверяемая идентичность поддерживает прямое OpenSSH-подключение; другой inventory transport не поддерживается.");
  return connection.credentialId || !connection.privateKeyPath
    ? connectionPrivateKey({ alias, address: connection.address, port: connection.port, user: connection.user }, connection.credentialId)
    : connection.privateKeyPath;
}

export async function observeAsset(alias: string, connection: AssetConnection): Promise<TrustedAssetObservation> {
  const privateKeyPath = assetPrivateKey(alias, connection);
  return probeTrustedAssetIdentity({ ...connection, user: connection.user!, privateKeyPath });
}

export async function captureAssetTarget(alias: string, connection: AssetConnection, expected?: VerifiedAssetBinding) {
  const observation = await observeAsset(alias, connection);
  if (expected && (expected.alias !== alias || expected.assetId !== assetIdForObservation(observation))) {
    throw Object.assign(new Error("Фактическая машина отличается от сохранённой идентичности операции. Выполнение или откат на другом активе запрещён."), { code: "asset_identity_changed" });
  }
  const binding = recordAssetObservation({ alias, connectionId: assetConnectionId(connection), observation });
  if (expected && binding.generation !== expected.generation) throw Object.assign(new Error("Привязка alias изменена после создания операции. Для старой резервной копии требуется отдельная ручная сверка."), { code: "asset_binding_stale" });
  return { binding, observation };
}

export async function captureAssetBinding(alias: string, connection: AssetConnection, expected?: VerifiedAssetBinding): Promise<VerifiedAssetBinding> {
  return (await captureAssetTarget(alias, connection, expected)).binding;
}

export function networkAssetBinding(alias: string, connection: AssetConnection): AssetBinding {
  return { version: 1, status: "unknown", alias, reason: "unauthenticated_network_scan", connectionId: assetConnectionId(connection),
    aliasGeneration: currentAssetBinding(alias)?.generation ?? null, observedAt: new Date().toISOString() };
}
