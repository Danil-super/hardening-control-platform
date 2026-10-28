"use client";

export type RecoveryEvidence = {
  confirmedHost: string; confirmedOperation: string; processesStopped: boolean;
  outcomeVerified: boolean; inspectionNote: string; evidenceReference: string;
};
export const emptyRecoveryEvidence: RecoveryEvidence = {
  confirmedHost: "", confirmedOperation: "", processesStopped: false,
  outcomeVerified: false, inspectionNote: "", evidenceReference: "",
};
export function recoveryEvidenceComplete(value: RecoveryEvidence, host: string, operation: string) {
  return value.confirmedHost === host && value.confirmedOperation === operation && value.processesStopped && value.outcomeVerified
    && value.inspectionNote.trim().length >= 20 && value.evidenceReference.trim().length >= 5;
}
const inputClass = "mt-1 w-full rounded-md border border-slate-700 bg-slate-950 p-2 text-sm text-white focus:border-sky-300 focus:outline-none";

export function OperationRecoveryFields({ host, operation, value, onChange, disabled }: {
  host: string; operation: string; value: RecoveryEvidence; onChange: (value: RecoveryEvidence) => void; disabled?: boolean;
}) {
  const set = <K extends keyof RecoveryEvidence>(key: K, next: RecoveryEvidence[K]) => onChange({ ...value, [key]: next });
  return <fieldset disabled={disabled} className="space-y-3 text-sm text-slate-200">
    <p className="leading-6 text-amber-100">Сначала остановите прежние процессы HCP и Ansible, включая процессы на цели, и проверьте хост через независимую консоль или отдельный SSH-доступ. Перезапуск HCP сам по себе не подтверждает остановку удалённой команды.</p>
    <label className="block">Введите alias: <strong>{host}</strong><input autoComplete="off" value={value.confirmedHost} onChange={event => set("confirmedHost", event.target.value)} className={inputClass} /></label>
    <label className="block">Введите ID операции: <span className="break-all font-mono">{operation}</span><input autoComplete="off" value={value.confirmedOperation} onChange={event => set("confirmedOperation", event.target.value)} className={inputClass} /></label>
    <label className="flex items-start gap-2"><input type="checkbox" className="mt-1" checked={value.processesStopped} onChange={event => set("processesStopped", event.target.checked)} />Прежние процессы HCP/Ansible и удалённая команда остановлены; параллельного выполнения нет.</label>
    <label className="flex items-start gap-2"><input type="checkbox" className="mt-1" checked={value.outcomeVerified} onChange={event => set("outcomeVerified", event.target.checked)} />Фактическое состояние цели проверено через независимый доступ.</label>
    <label className="block">Что проверено и какой результат получен<textarea rows={3} minLength={20} maxLength={2000} value={value.inspectionNote} onChange={event => set("inspectionNote", event.target.value)} className={inputClass} /></label>
    <label className="block">Ссылка или номер протокола проверки<input minLength={5} maxLength={500} value={value.evidenceReference} onChange={event => set("evidenceReference", event.target.value)} className={inputClass} /></label>
    <p className="text-xs text-slate-400">Пояснение и ссылка сохранятся в журнале. Не указывайте пароли и приватные ключи.</p>
  </fieldset>;
}
