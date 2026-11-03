"use client";

import { useEffect, useState } from "react";
import { CircleAlert, Database, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import {
  describeSourceAssignment, parseSourceGuidance, type SourceAssignment, type SourceGuidance,
} from "@/lib/host-source-guidance";

function SourceRow({
  title, description, source, href, action,
}: {
  title: string; description: string; source: SourceAssignment;
  href: string; action: string;
}) {
  const status = describeSourceAssignment(source);
  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-100">{title}</h4>
        <span className={`text-xs font-medium ${status.tone === "warning" ? "text-amber-200" : "text-slate-300"}`}>
          {status.label}
        </span>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-400">{description}</p>
      <p className="mt-2 text-xs leading-5 text-slate-300">{source.message}</p>
      {source.group ? <p className="mt-1 text-xs text-slate-400">Группа: {source.group}</p> : null}
      {source.declaredRelease ? <p className="mt-1 text-xs text-slate-400">Заявленный выпуск: {source.declaredRelease} (не проверен на хосте)</p> : null}
      <LinkButton href={href} variant="secondary"
        className="mt-3 [&]:min-h-8 [&]:rounded-lg [&]:px-3 [&]:py-1 [&]:text-xs">
        {action}
      </LinkButton>
    </div>
  );
}

/** Saves no source metadata and invokes no scanner: this is an operator aid. */
export function HostSourceGuidance({ alias }: { alias: string | null }) {
  const [loaded, setLoaded] = useState<SourceGuidance | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!alias) { setLoaded(null); setError(""); setLoading(false); return; }
    const controller = new AbortController();
    setLoaded(null);
    setError("");
    setLoading(true);
    async function load() {
      try {
        const response = await fetch(
          `/api/ansible/hosts/audit-preparation?alias=${encodeURIComponent(alias!)}`,
          { cache: "no-store", signal: controller.signal },
        );
        const payload = await readApiResponse(response) as unknown;
        const data = parseSourceGuidance(payload, alias!);
        if (!response.ok || !data) {
          const message = payload && typeof payload === "object" && "message" in payload
            && typeof payload.message === "string" ? payload.message : "Ответ о назначениях неполный.";
          throw new Error(message);
        }
        if (!controller.signal.aborted) setLoaded(data);
      } catch (cause) {
        if (!controller.signal.aborted) setError(errorMessage(cause, "Не удалось прочитать настройки проверки."));
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [alias]);

  if (!alias) return null;
  return (
    <section className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-4"
      aria-labelledby="host-source-guidance-title">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <Database size={16} className="text-sky-200" aria-hidden="true"/>
            <h3 id="host-source-guidance-title" className="text-sm font-semibold text-slate-100">
              Подготовка источников для {alias}
            </h3>
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Только сохранённые назначения: не проверяет фактическую ОС, применимость,
            наличие свежего XML или достоверность CVE. Никаких команд на целевом хосте.
          </p>
        </div>
        <LinkButton href={`/data-sources?host=${encodeURIComponent(alias)}#host-audit-preparation`}
          variant="secondary" className="[&]:min-h-8 [&]:rounded-lg [&]:px-3 [&]:py-1 [&]:text-xs">
          Источники и политики
        </LinkButton>
      </div>
      {loading ? <p role="status" className="mt-3 text-xs text-slate-300">Чтение сохранённых назначений…</p> : null}
      {error ? <p role="alert" className="mt-3 flex gap-2 text-xs text-amber-200">
        <CircleAlert size={16} className="shrink-0" aria-hidden="true"/>{error}
      </p> : null}
      {loaded && loaded.alias === alias ? (
        <>
          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            <SourceRow title="Astra OVAL" source={loaded.astraOval}
              description="Требуется только для отдельной CVE-оценки Astra по OVAL своего выпуска; для иных ОС отсутствие этой настройки не является ошибкой."
              href={`/data-sources?host=${encodeURIComponent(alias)}#astra-oval-title`}
              action="Проверить источник OVAL"/>
            <SourceRow title="Профиль OpenSCAP" source={loaded.openScap}
              description="Нужен только для выбранной конфигурационной проверки; назначение не подтверждает выполнение XCCDF/SCE."
              href="/policies" action="Проверить профиль"/>
          </div>
          <p className="mt-3 flex gap-2 text-xs leading-5 text-slate-400">
            <ShieldCheck size={16} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true"/>
            Перед запуском применимость проверяется по данным конкретного хоста и реальному результату сканера.
            Статус «Назначено» не означает успешный аудит.
          </p>
        </>
      ) : null}
    </section>
  );
}
