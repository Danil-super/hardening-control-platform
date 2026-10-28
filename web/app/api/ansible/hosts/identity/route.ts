import { NextResponse } from "next/server";
import { inventoryHostConnection, inventoryHostExists } from "@/lib/ansible-control";
import { assetConnectionId, assetIdForObservation, validAssetAlias } from "@/lib/asset-binding";
import { observeAsset } from "@/lib/asset-registry";
import { assetBindingHistory, currentAssetBinding, recordAssetObservation } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const alias = new URL(request.url).searchParams.get("alias");
  if (!validAssetAlias(alias)) return NextResponse.json({ ok: false, message: "Укажите alias хоста." }, { status: 400 });
  return NextResponse.json({ ok: true, current: currentAssetBinding(alias), history: assetBindingHistory(alias) });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const alias = body?.alias;
  if (!validAssetAlias(alias) || !inventoryHostExists(alias)) return NextResponse.json({ ok: false, message: "Выберите сохранённый хост." }, { status: 400 });
  try {
    const connection = inventoryHostConnection(alias);
    const observation = await observeAsset(alias, connection);
    const observedAssetId = assetIdForObservation(observation);
    const current = currentAssetBinding(alias);
    if (body.action === "rebind") {
      if (body.confirmedAlias !== alias || body.independentlyVerified !== true || !current) throw new Error("Подтвердите alias и независимую проверку машины и SSH fingerprint.");
      const binding = recordAssetObservation({ alias, connectionId: assetConnectionId(connection), observation }, {
        expectedGeneration: body.expectedGeneration, expectedAssetId: body.expectedAssetId, observedAssetId: body.observedAssetId,
        reason: typeof body.reason === "string" ? body.reason : "",
      });
      return NextResponse.json({ ok: true, status: "verified", current: binding, message: "Новая привязка сохранена. Исторические отчёты и резервные копии остались связаны с прежней идентичностью." });
    }
    if (body.action !== "check") throw new Error("Укажите действие check или rebind.");
    if (current && current.assetId !== observedAssetId) return NextResponse.json({ ok: false, status: "changed", current,
      observed: { machineIdSha256: observation.machineIdSha256, sshHostKeyFingerprint: observation.sshHostKeyFingerprint,
        observedAt: observation.observedAt, assetId: observedAssetId }, message: "Машина или SSH host key изменились. Проверьте новую идентичность независимо и подтвердите перепривязку." }, { status: 409 });
    const binding = recordAssetObservation({ alias, connectionId: assetConnectionId(connection), observation });
    return NextResponse.json({ ok: true, status: "verified", current: binding, message: "Идентичность проверена через SSH. Новые запуски повторят эту проверку." });
  } catch (error) {
    return NextResponse.json({ ok: false, status: "error", message: error instanceof Error ? error.message : "Не удалось проверить идентичность." }, { status: 409 });
  }
}
