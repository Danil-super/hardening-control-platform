"use client";

import { useState } from "react";
import { AlertTriangle, LoaderCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { errorMessage, readApiResponse } from "@/lib/client-api";

type Host = { alias: string; address: string; user: string | null; credentialReady?: boolean };

export function DecommissionHostDialog({ host, onClose, onCompleted }: { host: Host; onClose: () => void; onCompleted: () => Promise<void> | void }) {
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function complete() {
    setBusy(true); setMessage("");
    try {
      const response = await fetch("/api/ansible/hosts/decommission", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alias: host.alias, confirmation }) });
      const payload = await readApiResponse(response) as { ok?: boolean; message?: string };
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось завершить работы по хосту.");
      await onCompleted();
      onClose();
    } catch (error) { setMessage(errorMessage(error, "Не удалось завершить работы по хосту.")); }
    finally { setBusy(false); }
  }
  return <div className="fixed inset-0 z-50 flex items-end bg-slate-950/80 p-4 backdrop-blur-sm sm:items-center sm:justify-center" role="dialog" aria-modal="true" aria-labelledby="decommission-title">
    <section className="w-full max-w-xl rounded-xl border border-red-400/35 bg-slate-950 p-5 shadow-2xl"><div className="flex items-start justify-between gap-4"><div className="flex gap-3"><AlertTriangle className="mt-0.5 shrink-0 text-red-200" aria-hidden="true" /><div><h2 id="decommission-title" className="text-lg font-semibold text-white">Завершить работы по хосту</h2><p className="mt-2 text-sm leading-6 text-slate-300">{host.alias} · {host.address}</p></div></div><button type="button" onClick={onClose} disabled={busy} aria-label="Закрыть" className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-white"><X size={20} aria-hidden="true" /></button></div>
      <div className="mt-4 rounded-lg border border-red-400/25 bg-red-500/10 p-4 text-sm leading-6 text-red-50"><p className="font-semibold">Будет отозван только доступ HCP к этому хосту.</p><ul className="mt-2 list-disc space-y-1 pl-5"><li>по закреплённому SSH-ключу сервера удалится ровно индивидуальный публичный ключ HCP из authorized_keys;</li><li>после успешного отзыва удалятся локальная пара ключей HCP и строка хоста из inventory;</li><li>отчёты, история решений, журнал и резервные копии останутся сохранёнными;</li><li>доверенный ключ SSH-сервера останется в HCP: это запись о подлинности, а не доступ.</li></ul></div>
      {!host.credentialReady ? <p className="mt-3 text-sm leading-6 text-amber-100">Для этого хоста не видна подтверждённая индивидуальная пара ключей. Операция будет остановлена, а старый общий ключ нужно отзывать вручную.</p> : null}
      <label className="mt-4 block text-sm text-slate-200">Введите alias <span className="font-semibold text-white">{host.alias}</span> для подтверждения<input autoFocus className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-white focus:border-sky-300 focus:outline-none" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
      {message ? <p className="mt-3 rounded-md border border-red-400/35 bg-red-500/10 p-3 text-sm leading-6 text-red-100" role="alert">{message}</p> : null}
      <div className="mt-5 flex flex-wrap justify-end gap-3"><Button variant="secondary" onClick={onClose} disabled={busy}>Отмена</Button><Button variant="danger" onClick={() => void complete()} disabled={busy || confirmation !== host.alias}>{busy ? <LoaderCircle className="animate-spin" size={16} aria-hidden="true" /> : null}{busy ? "Отзываем доступ…" : "Отозвать доступ и завершить"}</Button></div>
    </section>
  </div>;
}
