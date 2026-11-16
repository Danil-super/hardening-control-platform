"use client";

import { useEffect, useState } from "react";
import { Button, LinkButton } from "@/components/ui/button";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import type { OvalPreparationStatus } from "@/lib/astra-oval-preparation";

type Payload = { ok?: boolean; message?: string; group?: string; source?: { mode: string; url: string; path: string; sha256: string; releasePattern: string }; preparation?: OvalPreparationStatus };
export function OvalPreparation({ alias }: { alias: string }) {
  const [payload, setPayload] = useState<Payload | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setPayload(null); setError("");
    async function load() {
      try {
        const response = await fetch(`/api/ansible/hosts/oval-preparation?alias=${encodeURIComponent(alias)}`, { cache: "no-store", signal: controller.signal });
        const value = await readApiResponse(response) as Payload;
        if (!response.ok || !value.ok) throw new Error(value.message ?? "Не удалось проверить готовность базы.");
        if (!controller.signal.aborted) { setPayload(value); setError(""); if (value.preparation?.state === "preparing") timer = setTimeout(load, 3000); }
      } catch (cause) { if (!controller.signal.aborted) setError(errorMessage(cause, "Не удалось проверить базу.")); }
    }
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [alias, refresh]);
  async function prepare() {
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/ansible/hosts/oval-preparation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alias }) });
      const value = await readApiResponse(response) as Payload;
      if (!response.ok || !value.ok) throw new Error(value.message ?? "Подготовка не запущена.");
      setRefresh(v => v + 1);
    } catch (cause) { setError(errorMessage(cause, "Подготовка не запущена.")); }
    finally { setBusy(false); }
  }
  const status = payload?.preparation;
  return <section id="oval-preparation" aria-labelledby="oval-preparation-title" className="mt-4 rounded-lg border border-sky-400/25 bg-slate-950/70 p-4">
    <h3 id="oval-preparation-title" className="font-semibold text-slate-100">База Astra OVAL</h3>
    <details className="mt-3 text-xs text-slate-400"><summary className="cursor-pointer text-sky-200">Источник и этапы подготовки</summary>    <ol className="mt-3 grid gap-2 text-xs leading-5 text-slate-300 md:grid-cols-3">
      <li><strong className="text-sky-200">1. Выберите источник.</strong> В «Источниках» сохраните группу, выпуск, архитектуру, прямой XML и ожидаемый SHA-256.</li>
      <li><strong className="text-sky-200">2. Подготовьте копию.</strong> Контроллер проверит HTTPS-доступ, загрузит базу, проверит SHA-256, возраст, XSD и Schematron. Хост не изменяется.</li>
      <li><strong className="text-sky-200">3. Запустите проверку.</strong> Только после готовности нажмите «Запустить проверку». Используется подготовленная копия без повторной загрузки; применимость проверяется на хосте.</li>
    </ol>
    {payload?.source ? <div className="mt-3 space-y-1 break-all text-xs text-slate-400"><p>Группа: {payload.group} · выпуск: {payload.source.releasePattern}</p><p>{payload.source.mode === "online" ? payload.source.url : payload.source.path}</p><p>Ожидаемый SHA-256: {payload.source.sha256}</p></div> : null}
</details>
    <p role="status" className={`mt-3 text-sm leading-6 ${status?.state === "ready" ? "text-emerald-200" : "text-slate-300"}`}>{status?.message ?? (!error ? "Чтение состояния базы…" : "Готовность не подтверждена.")}</p>
    {status?.state === "ready" ? <p className="mt-2 text-xs text-slate-400">Размер: {status.bytes?.toLocaleString("ru-RU")} байт · дата базы: {status.generatedAt} · подготовлена: {status.finishedAt ? new Date(status.finishedAt).toLocaleString("ru-RU") : "—"}. Подготовка базы не является аудитом хоста.</p> : null}
    {error ? <p role="alert" className="mt-2 text-sm text-amber-200">{error}</p> : null}
    <div className="mt-3 flex flex-wrap gap-2">
      {status && status.state !== "local" ? <Button variant="secondary" onClick={() => void prepare()} disabled={busy || status.state === "preparing"}>{busy || status.state === "preparing" ? "База подготавливается…" : status.state === "ready" ? "Перепроверить копию" : "Подготовить и проверить базу"}</Button> : null}
      <LinkButton href={`/data-sources?host=${encodeURIComponent(alias)}#astra-oval-title`} variant="secondary">Источник и SHA-256</LinkButton>
      <Button variant="secondary" onClick={() => setRefresh(v => v + 1)} disabled={busy}>Обновить состояние</Button>
    </div>
    <p className="mt-3 text-xs leading-5 text-slate-500">После смены источника подготовьте базу заново.</p>
  </section>;
}
