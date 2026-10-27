"use client";

import { useEffect, useId, useRef, useState } from "react";
import { Archive, RotateCcw, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { useNotify } from "@/components/ui/feedback";
import { useAuditJobs } from "@/components/hosts/audit-jobs-provider";
import { readApiResponse, errorMessage } from "@/lib/client-api";

type Preview = { total: number; reports: number; pdf: number; journal: number; token: string };

export function ArchiveControls({ target, archived = false, onChanged }: { target: "reports" | "journal"; archived?: boolean; onChanged?: () => void | Promise<void> }) {
  const router = useRouter();
  const notify = useNotify();
  const { jobs } = useAuditJobs();
  const active = jobs.some((job) => job.status === "queued" || job.status === "running");
  const action = archived ? "restore" : "archive";
  const label = archived ? "Вернуть из архива" : target === "reports" ? "Очистить все отчёты" : "Очистить журнал";
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  useEffect(() => {
    if (open && !dialog.current?.open) dialog.current?.showModal();
    if (!open && dialog.current?.open) dialog.current.close();
  }, [open]);

  async function inspect() {
    setOpen(true); setBusy(true); setPreview(null); setChecked(false); setError("");
    try {
      const response = await fetch(`/api/ansible/archive?target=${target}&action=${action}`, { cache: "no-store" });
      const payload = await readApiResponse(response);
      if (!response.ok || !payload.ok || typeof payload.preview?.total !== "number" || typeof payload.preview?.token !== "string") throw new Error(payload.message ?? "Не удалось получить список для очистки.");
      setPreview(payload.preview);
    } catch (cause) { setError(errorMessage(cause, "Не удалось прочитать список.")); }
    finally { setBusy(false); }
  }

  async function confirm() {
    if (!checked || !preview || !preview.total) return;
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/ansible/archive", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, action, token: preview.token, confirmation: `${action}:${target}` }) });
      const payload = await readApiResponse(response);
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось выполнить операцию.");
      if (onChanged) await onChanged();
      setOpen(false); router.refresh(); notify(payload.message ?? "Список обновлён.", "success");
    } catch (cause) { setError(errorMessage(cause, "Не удалось обновить список.")); setChecked(false); }
    finally { setBusy(false); }
  }

  return <>
    <Button ref={trigger} variant="secondary" onClick={() => void inspect()} disabled={busy || active} title={active ? "Дождитесь завершения выполняемых проверок" : undefined}>{archived ? <RotateCcw size={15} aria-hidden="true" /> : <Archive size={15} aria-hidden="true" />}{label}</Button>
    <dialog ref={dialog} aria-labelledby={titleId} onClose={() => { setOpen(false); trigger.current?.focus(); }} className="fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-full max-w-[calc(100vw-2rem)] overflow-y-auto rounded-xl border border-slate-700 bg-slate-950 p-5 text-slate-200 backdrop:bg-slate-950/80 sm:max-w-xl">
      <div className="flex items-start justify-between gap-3"><h2 id={titleId} className="text-lg font-semibold text-white">{label}</h2><Button variant="secondary" className="px-2" aria-label="Закрыть" onClick={() => setOpen(false)}><X size={16} aria-hidden="true" /></Button></div>
      <p className="mt-3 text-sm leading-6 text-slate-300">{archived ? "Архивные записи вернутся в активные списки." : target === "reports" ? "Все отчёты проверок и итоговые PDF всех хостов будут убраны из активных списков. Старые проверки перестанут учитываться в текущей сводке рисков. Файлы, план работ, история изменений и доказательства сохранятся в архиве." : "Все текущие записи журнала будут убраны в архив. Подписанная история останется целой; новые действия появятся в активном журнале."}</p>
      {busy && !preview ? <p className="mt-4 text-sm text-slate-400" role="status">Подсчитываю записи…</p> : preview ? <p className="mt-4 rounded-lg border border-slate-800 p-3 text-sm">{target === "reports" ? `Отчёты проверок: ${preview.reports} · Итоговые PDF: ${preview.pdf}` : `Записи журнала: ${preview.journal}`}</p> : null}
      {error ? <p role="alert" className="mt-3 text-sm text-red-200">{error}</p> : null}
      {preview?.total ? <label className="mt-4 flex items-start gap-2 text-sm leading-6"><input type="checkbox" checked={checked} disabled={busy} onChange={(event) => setChecked(event.target.checked)} className="mt-1.5 h-4 w-4 shrink-0" />{archived ? "Подтверждаю возврат перечисленных записей" : "Подтверждаю очистку активного списка с сохранением архива"}</label> : preview ? <p className="mt-3 text-sm text-slate-400">В этом списке нет записей для обработки.</p> : null}
      <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => void confirm()} disabled={busy || !checked || !preview?.total || active}>{busy && preview ? "Обработка…" : archived ? "Восстановить записи" : "Переместить в архив"}</Button>{error ? <Button variant="secondary" onClick={() => void inspect()} disabled={busy}>Перепроверить</Button> : null}<Button variant="secondary" onClick={() => setOpen(false)}>Отмена</Button></div>
    </dialog>
  </>;
}
