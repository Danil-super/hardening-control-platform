"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { errorMessage, readApiResponse } from "@/lib/client-api";
import { emptyRecoveryEvidence, OperationRecoveryFields, recoveryEvidenceComplete } from "@/components/hosts/operation-recovery-fields";

export function RemediationRecovery({ transaction, onRecovered }: {
  transaction: { id: string; hostAlias: string; status: string; backupRef: string | null; recoveryVersion: string };
  onRecovered: () => Promise<void> | void;
}) {
  const [evidence, setEvidence] = useState(emptyRecoveryEvidence);
  const [resolution, setResolution] = useState("");
  const [backupVerified, setBackupVerified] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const ready = recoveryEvidenceComplete(evidence, transaction.hostAlias, transaction.id) && resolution && (resolution !== "prepare_rollback" || backupVerified);
  async function recover() {
    setBusy(true); setMessage("");
    try {
      const response = await fetch(`/api/ansible/remediations/${encodeURIComponent(transaction.id)}/recover`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...evidence, resolution, backupVerified, expectedRecoveryVersion: transaction.recoveryVersion }),
      });
      const payload = await readApiResponse(response) as { ok?: boolean; message?: string };
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось зарегистрировать сверку.");
      setMessage(payload.message ?? "Результат записан в журнал.");
      setEvidence(emptyRecoveryEvidence); setResolution(""); setBackupVerified(false);
      await onRecovered();
    } catch (error) { setMessage(errorMessage(error, "Не удалось зарегистрировать сверку.")); }
    finally { setBusy(false); }
  }
  return <details className="mt-3 rounded-md border border-amber-400/30 bg-amber-400/5 p-3">
    <summary className="cursor-pointer text-sm font-semibold text-amber-100">{transaction.status === "recovery_ready" ? "Хост заблокирован до отката; зарегистрировать ручное восстановление" : "Операция прервана или её владелец неизвестен: сверить состояние"}</summary>
    <form className="mt-4 space-y-4" onSubmit={event => { event.preventDefault(); void recover(); }}>
      <OperationRecoveryFields host={transaction.hostAlias} operation={transaction.id} value={evidence} onChange={setEvidence} disabled={busy} />
      <label className="block text-sm text-slate-200">Результат независимой проверки<select className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 p-2" value={resolution} onChange={event => setResolution(event.target.value)} disabled={busy}>
        <option value="">Выберите подтверждённый результат</option>
        {!transaction.backupRef && transaction.status !== "recovery_ready" ? <option value="not_applied">Изменение не начиналось, исходное состояние подтверждено</option> : null}
        <option value="prepare_rollback">Исходная резервная копия проверена; подготовить отдельный откат</option>
        <option value="restored_manually">Исходное состояние полностью восстановлено вручную</option>
      </select></label>
      {resolution === "prepare_rollback" ? <label className="flex items-start gap-2 text-sm text-slate-200"><input type="checkbox" checked={backupVerified} onChange={event => setBackupVerified(event.target.checked)} disabled={busy} className="mt-1" />На целевом хосте проверены исходная копия этой операции, metadata.json, контрольная сумма и идентичность хоста. Хост останется заблокирован до успешного отката.</label> : null}
      {message ? <p role="status" className="text-sm text-amber-100">{message}</p> : null}
      <Button type="submit" variant="secondary" disabled={busy || !ready}>{busy ? "Сохраняем…" : "Записать результат сверки"}</Button>
    </form>
  </details>;
}
