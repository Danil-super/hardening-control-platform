"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import type { AssetObservation, VerifiedAssetBinding } from "@/lib/asset-binding";

type Result = { ok?: boolean; status?: string; message?: string; current?: VerifiedAssetBinding | null;
  observed?: AssetObservation & { assetId: string }; history?: { binding: VerifiedAssetBinding; reason: string }[] };

export function AssetIdentityPanel({ alias }: { alias: string }) {
  const [result, setResult] = useState<Result>({});
  const [busy, setBusy] = useState(false);
  const [confirmedAlias, setConfirmedAlias] = useState("");
  const [reason, setReason] = useState("");
  const [verified, setVerified] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    setResult({}); setConfirmedAlias(""); setReason(""); setVerified(false);
    void fetch(`/api/ansible/hosts/identity?alias=${encodeURIComponent(alias)}`, { signal: controller.signal })
      .then((response) => response.json()).then((value) => { if (!controller.signal.aborted) setResult(value); })
      .catch(() => { if (!controller.signal.aborted) setResult({ ok: false, message: "Не удалось прочитать привязку актива." }); });
    return () => controller.abort();
  }, [alias]);
  async function submit(action: "check" | "rebind") {
    setBusy(true);
    try {
      const response = await fetch("/api/ansible/hosts/identity", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias, action, confirmedAlias, independentlyVerified: verified, reason,
          expectedGeneration: result.current?.generation, expectedAssetId: result.current?.assetId, observedAssetId: result.observed?.assetId }) });
      const next: Result = await response.json();
      setResult(next);
      setConfirmedAlias(""); setVerified(false);
    } catch { setResult((previous) => ({ ...previous, ok: false, message: "Проверка идентичности не завершена." })); }
    finally { setBusy(false); }
  }
  const binding = result.current;
  return <section className="mt-4 rounded-xl border border-slate-700 p-4">
    <h3 className="font-semibold text-white">Идентичность актива</h3>
    <p className="mt-2 text-sm text-slate-300">Привязка использует machine-id и проверенный SSH host key. IP или имя inventory сами по себе не подтверждают прежнюю машину.</p>
    {binding ? <div className="mt-3 space-y-1 break-all text-xs text-slate-300">
      <p>Актив: {binding.assetId} · поколение {binding.generation}</p><p>SSH: {binding.sshHostKeyFingerprint}</p><p>Последнее сохранённое подтверждение: {binding.verifiedAt}</p>
    </div> : <p className="mt-3 text-sm text-amber-100">Проверенной привязки пока нет. Старые отчёты останутся без идентичности актива.</p>}
    <Button type="button" variant="secondary" className="mt-3" disabled={busy} onClick={() => void submit("check")}>{busy ? "Проверяем…" : "Проверить идентичность через SSH"}</Button>
    {result.status === "changed" && result.observed && binding ? <div className="mt-4 space-y-3 rounded-lg border border-amber-400/40 p-4 text-sm text-amber-100">
      <p>Обнаружена другая идентичность. Подтверждение создаст новое поколение привязки. Старые отчёты не станут отчётами новой машины; автоматический откат старой резервной копии будет заблокирован.</p>
      <p className="break-all">Новый актив: {result.observed.assetId}<br />Новый SSH fingerprint: {result.observed.sshHostKeyFingerprint}<br />Hash machine-id: {result.observed.machineIdSha256}</p>
      <label className="block">Для подтверждения введите {alias}<input value={confirmedAlias} onChange={(event) => setConfirmedAlias(event.target.value)} className="mt-1 block w-full rounded bg-slate-900 p-2 text-white" /></label>
      <label className="block">Причина и протокол независимой проверки<textarea value={reason} onChange={(event) => setReason(event.target.value)} minLength={20} maxLength={2000} className="mt-1 block w-full rounded bg-slate-900 p-2 text-white" /></label>
      <label className="flex gap-2"><input type="checkbox" checked={verified} onChange={(event) => setVerified(event.target.checked)} />Я сверил машину и SSH fingerprint через независимый доступ и понимаю смену привязки.</label>
      <Button type="button" variant="danger" disabled={busy || confirmedAlias !== alias || !verified || reason.trim().length < 20} onClick={() => void submit("rebind")}>Подтвердить новую привязку</Button>
    </div> : null}
    {result.message ? <p role={result.ok === false ? "alert" : "status"} className={`mt-3 text-sm ${result.ok === false ? "text-amber-100" : "text-slate-300"}`}>{result.message}</p> : null}
    {(result.history?.length ?? 0) > 1 ? <details className="mt-3 text-xs text-slate-400"><summary>История привязок</summary>{result.history!.map((entry) => <p key={entry.binding.generation} className="mt-2 break-all">Поколение {entry.binding.generation}: {entry.binding.assetId}. {entry.reason}</p>)}</details> : null}
  </section>;
}
