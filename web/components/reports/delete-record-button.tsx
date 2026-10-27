"use client";

import { LockKeyhole, Trash2, X } from "lucide-react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useEffect, useId, useRef, useState } from "react";
import { useNotify } from "@/components/ui/feedback";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button } from "@/components/ui/button";

type DeleteRecordButtonProps = {
  endpoint: string;
  dependenciesEndpoint?: string;
  confirmation: string;
  body?: Record<string, string>;
  label?: string;
  onDeleted?: () => void | Promise<void>;
};

type DeleteDependency = { id: string; label: string; href: string; description?: string };

function dependencyList(value: unknown): DeleteDependency[] {
  return Array.isArray(value) ? value.filter((item): item is DeleteDependency => item && typeof item.id === "string" && typeof item.label === "string" && typeof item.href === "string" && item.href.startsWith("/") && !item.href.startsWith("//") && (item.description === undefined || typeof item.description === "string")) : [];
}

export function DeleteRecordButton({ endpoint, dependenciesEndpoint, confirmation, body, label = "Удалить", onDeleted }: DeleteRecordButtonProps) {
  const router = useRouter();
  const notify = useNotify();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [references, setReferences] = useState<DeleteDependency[]>([]);
  const [usageMessage, setUsageMessage] = useState("");
  const [checking, setChecking] = useState(false);
  const [open, setOpen] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  useEffect(() => {
    if (open && !dialog.current?.open) dialog.current?.showModal();
    else if (!open && dialog.current?.open) dialog.current.close();
  }, [open]);

  function showUsage(payload: { message?: string; references?: unknown }) {
    setUsageMessage(payload.message ?? "Отчёт используется в других записях.");
    setReferences(dependencyList(payload.references));
    setOpen(true);
  }

  async function remove() {
    if (!dependenciesEndpoint && !window.confirm(confirmation)) {
      return;
    }
    setPending(true);
    setError("");
    setReferences([]);
    try {
      if (dependenciesEndpoint) {
        setChecking(true);
        const preview = await fetch(dependenciesEndpoint, { cache: "no-store" });
        const usage = await readApiResponse(preview);
        if (!preview.ok || !usage.ok || typeof usage.canDelete !== "boolean") throw new Error(usage.message ?? "Не удалось проверить использование отчёта.");
        if (!usage.canDelete) { showUsage(usage); return; }
        setChecking(false);
        if (!window.confirm(confirmation)) return;
      }
      const response = await fetch(endpoint, {
        method: "DELETE",
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const payload = await readApiResponse(response);
      if (!response.ok || !payload.ok) {
        if (response.status === 409 && Array.isArray(payload.references)) { showUsage(payload); return; }
        throw new Error(payload.message ?? "Не удалось удалить запись.");
      }
      notify(payload.message || "Запись удалена.", "success");
      if (onDeleted) await onDeleted(); else router.refresh();
    } catch (cause) {
      const message = errorMessage(cause, "Не удалось удалить запись. Проверьте соединение.");
      setError(message);
      notify(message, "error");
    } finally {
      setPending(false);
      setChecking(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button ref={trigger} type="button" variant="danger" className="h-9 px-3" onClick={remove} disabled={pending}>
        <Trash2 size={15} aria-hidden="true" />
        {pending ? checking ? "Проверяю…" : "Удаление…" : label}
      </Button>
      {error ? <p className="max-w-48 text-xs text-red-200">{error}</p> : null}
      {references.length ? <button type="button" onClick={() => setOpen(true)} className="inline-flex min-h-6 items-center gap-1 text-xs text-sky-200 underline underline-offset-2"><LockKeyhole size={12} aria-hidden="true" />Где используется ({references.length})</button> : null}
      <dialog ref={dialog} aria-labelledby={titleId} onClose={() => { setOpen(false); trigger.current?.focus(); }} className="fixed inset-0 m-auto max-h-[calc(100dvh-2rem)] w-full max-w-[calc(100vw-2rem)] overflow-y-auto rounded-xl border border-slate-700 bg-slate-950 p-5 text-slate-200 shadow-xl backdrop:bg-slate-950/80 sm:max-w-xl">
        <div className="flex items-start justify-between gap-3"><h2 id={titleId} className="text-lg font-semibold text-white">Почему отчёт нельзя удалить</h2><Button type="button" variant="secondary" aria-label="Закрыть" onClick={() => setOpen(false)} className="px-2"><X size={16} aria-hidden="true" /></Button></div>
        <p className="mt-3 text-sm leading-6 text-slate-300">{usageMessage}</p>
        <ul className="mt-4 space-y-3">{references.map((item) => <li key={item.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <p className="break-words text-sm font-semibold text-white">{item.label}</p>
          {item.description ? <p className="mt-1 break-words text-sm leading-6 text-slate-400">{item.description}</p> : null}
          <Link href={item.href} prefetch={false} onClick={() => setOpen(false)} className="mt-2 inline-flex min-h-8 items-center text-sm text-sky-200 underline underline-offset-4" aria-label={`Открыть: ${item.label}`}>Открыть запись</Link>
        </li>)}</ul>
      </dialog>
    </div>
  );
}
