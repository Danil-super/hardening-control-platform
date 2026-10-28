"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle, LoaderCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { errorMessage, readApiResponse } from "@/lib/client-api";
import { emptyRecoveryEvidence, OperationRecoveryFields, recoveryEvidenceComplete } from "@/components/hosts/operation-recovery-fields";

type Host = { alias: string; address: string; user: string | null; credentialReady?: boolean };
type CloseoutStatus = { credentialId: string | null; recoveryRequired: boolean; recoveryVersion: string | null; ownerLive: boolean; status: string | null };

export function DecommissionHostDialog({ host, onClose, onCompleted }: { host: Host; onClose: () => void; onCompleted: () => Promise<void> | void }) {
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [checking, setChecking] = useState(true);
  const [status, setStatus] = useState<CloseoutStatus | null>(null);
  const [evidence, setEvidence] = useState(emptyRecoveryEvidence);
  const [resolution, setResolution] = useState("");
  const [remoteKeyAbsent, setRemoteKeyAbsent] = useState(false);
  const [sudoRuleResolved, setSudoRuleResolved] = useState(false);
  const lastRecoveryVersion = useRef<string | null | undefined>(undefined);
  async function loadStatus(signal?: AbortSignal) {
    setChecking(true);
    try {
      const response = await fetch(`/api/ansible/hosts/decommission?alias=${encodeURIComponent(host.alias)}`, { signal });
      const payload = await readApiResponse(response) as CloseoutStatus & { ok?: boolean; message?: string };
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать состояние отзыва.");
      if (!signal?.aborted) {
        if (lastRecoveryVersion.current !== payload.recoveryVersion) {
          setEvidence(emptyRecoveryEvidence); setResolution(""); setRemoteKeyAbsent(false); setSudoRuleResolved(false);
          lastRecoveryVersion.current = payload.recoveryVersion;
        }
        setStatus(payload);
      }
    } catch (error) { if (!signal?.aborted) { setStatus(null); setMessage(errorMessage(error, "Не удалось прочитать состояние отзыва.")); } }
    finally { if (!signal?.aborted) setChecking(false); }
  }
  useEffect(() => {
    const controller = new AbortController();
    void loadStatus(controller.signal);
    return () => controller.abort();
  // The dialog is tied to one alias; other changes do not reload its form.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host.alias]);
  const recovering = Boolean(status?.recoveryRequired);
  const canRecover = Boolean(status?.credentialId && recoveryEvidenceComplete(evidence, host.alias, status.credentialId)
    && resolution && (resolution !== "remote_absent" || remoteKeyAbsent && sudoRuleResolved));
  async function complete() {
    setBusy(true); setMessage("");
    try {
      const body = recovering ? { alias: host.alias, confirmation: evidence.confirmedHost, recover: true,
        credentialId: status?.credentialId, expectedRecoveryVersion: status?.recoveryVersion, ...evidence, resolution, remoteKeyAbsent, sudoRuleResolved } : { alias: host.alias, confirmation };
      const response = await fetch("/api/ansible/hosts/decommission", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const payload = await readApiResponse(response) as { ok?: boolean; message?: string; completed?: boolean };
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось завершить работы по хосту.");
      if (recovering && payload.completed === false) {
        setConfirmation(""); setEvidence(emptyRecoveryEvidence); setResolution("");
        await loadStatus(); setMessage(payload.message ?? "Сверка записана. Новый отзыв запускается отдельно."); return;
      }
      await onCompleted();
      onClose();
    } catch (error) { await loadStatus(); setMessage(errorMessage(error, "Не удалось завершить работы по хосту.")); }
    finally { setBusy(false); }
  }
  return <div className="fixed inset-0 z-50 flex items-end bg-slate-950/80 p-4 backdrop-blur-sm sm:items-center sm:justify-center" role="dialog" aria-modal="true" aria-labelledby="decommission-title">
    <section className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-xl border border-red-400/35 bg-slate-950 p-5 shadow-2xl"><div className="flex items-start justify-between gap-4"><div className="flex gap-3"><AlertTriangle className="mt-0.5 shrink-0 text-red-200" aria-hidden="true" /><div><h2 id="decommission-title" className="text-lg font-semibold text-white">Завершить работы по хосту</h2><p className="mt-2 text-sm leading-6 text-slate-300">{host.alias} · {host.address}</p></div></div><button type="button" onClick={onClose} disabled={busy} aria-label="Закрыть" className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-white"><X size={20} aria-hidden="true" /></button></div>
      <div className="mt-4 rounded-lg border border-red-400/25 bg-red-500/10 p-4 text-sm leading-6 text-red-50"><p className="font-semibold">Будет отозван только доступ HCP к этому хосту.</p><ul className="mt-2 list-disc space-y-1 pl-5"><li>по закреплённому SSH-ключу сервера удалится ровно индивидуальный публичный ключ HCP из authorized_keys;</li><li>после успешного отзыва удалятся локальная пара ключей HCP и строка хоста из inventory;</li><li>отчёты, история решений, журнал и резервные копии останутся сохранёнными;</li><li>доверенный ключ SSH-сервера останется в HCP: это запись о подлинности, а не доступ.</li></ul></div>
      {status?.ownerLive ? <p className="mt-3 text-sm leading-6 text-amber-100">Прежний процесс ещё выполняется. Его блокировку нельзя снять через восстановление. Дождитесь завершения и обновите состояние.</p> : null}
      {recovering && status?.credentialId ? <div className="mt-4 space-y-4">
        <p className="text-sm leading-6 text-amber-100">Предыдущий отзыв не завершён. Повторное удаление ключа не запускается. Зарегистрируйте результат независимой проверки, чтобы безопасно завершить локальную очистку.</p>
        <OperationRecoveryFields host={host.alias} operation={status.credentialId} value={evidence} onChange={setEvidence} disabled={busy || status.ownerLive} />
        <label className="block text-sm text-slate-200">Подтверждённый результат<select className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 p-2" value={resolution} onChange={event => setResolution(event.target.value)} disabled={busy || status.ownerLive}>
          <option value="">Выберите результат</option>
          <option value="remote_absent">Ключ HCP отсутствует на цели; завершить локальную очистку</option>
          {!["remote_revoked", "remote_partial", "completed"].includes(status.status ?? "") ? <option value="not_changed">Удалённые изменения не произошли; разрешить отдельную новую попытку</option> : null}
        </select></label>
        {resolution === "remote_absent" ? <div className="space-y-2 text-sm text-slate-200">
          <label className="flex items-start gap-2"><input type="checkbox" checked={remoteKeyAbsent} onChange={event => setRemoteKeyAbsent(event.target.checked)} disabled={busy} className="mt-1" />Проверено отсутствие именно индивидуального публичного ключа HCP в authorized_keys на цели.</label>
          <label className="flex items-start gap-2"><input type="checkbox" checked={sudoRuleResolved} onChange={event => setSudoRuleResolved(event.target.checked)} disabled={busy} className="mt-1" />Управляемое HCP правило sudoers удалено, либо подтверждено, что оно не создавалось.</label>
        </div> : null}
      </div> : <>
        {!host.credentialReady ? <p className="mt-3 text-sm leading-6 text-amber-100">Для этого хоста не видна подтверждённая индивидуальная пара ключей. Операция будет остановлена, а старый общий ключ нужно отзывать вручную.</p> : null}
        <label className="mt-4 block text-sm text-slate-200">Введите alias <span className="font-semibold text-white">{host.alias}</span> для подтверждения<input autoFocus className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-white focus:border-sky-300 focus:outline-none" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
      </>}
      {message ? <p className="mt-3 rounded-md border border-red-400/35 bg-red-500/10 p-3 text-sm leading-6 text-red-100" role="alert">{message}</p> : null}
      <div className="mt-5 flex flex-wrap justify-end gap-3"><Button variant="secondary" onClick={() => void loadStatus()} disabled={busy || checking}>Обновить состояние</Button><Button variant="secondary" onClick={onClose} disabled={busy}>Отмена</Button><Button variant="danger" onClick={() => void complete()} disabled={busy || checking || !status || status.ownerLive || (recovering ? !canRecover : confirmation !== host.alias)}>{busy ? <LoaderCircle className="animate-spin" size={16} aria-hidden="true" /> : null}{busy ? "Выполняется…" : recovering ? "Записать сверку и завершить" : "Отозвать доступ и завершить"}</Button></div>
    </section>
  </div>;
}
