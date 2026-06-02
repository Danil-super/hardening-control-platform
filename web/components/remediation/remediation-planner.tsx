"use client";

import { CheckCircle2, DatabaseBackup, Download, Loader2, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { RiskBadge } from "@/components/ui/badge";
import { Button, LinkButton } from "@/components/ui/button";
import { remediationSteps, createBeforeAfterReport } from "@/lib/demo-audit";
import { serializeReport } from "@/lib/report-utils";
import type { Remediation } from "@/types";

export function RemediationPlanner({
  profileId,
  remediations,
}: {
  profileId: string;
  remediations: Remediation[];
}) {
  const [selected, setSelected] = useState<string[]>(remediations.map((remediation) => remediation.id));
  const [step, setStep] = useState(-1);
  const [complete, setComplete] = useState(false);

  const selectedRemediations = useMemo(
    () => remediations.filter((remediation) => selected.includes(remediation.id)),
    [remediations, selected],
  );

  function toggle(remediationId: string) {
    setSelected((current) =>
      current.includes(remediationId)
        ? current.filter((id) => id !== remediationId)
        : [...current, remediationId],
    );
  }

  function applyDemo() {
    setStep(0);
    setComplete(false);

    remediationSteps.forEach((_, index) => {
      window.setTimeout(() => setStep(index), index * 700);
    });

    window.setTimeout(() => {
      const report = createBeforeAfterReport(profileId, selected);
      window.localStorage.setItem("hcp:last-report", serializeReport(report));
      setComplete(true);
    }, remediationSteps.length * 700 + 300);
  }

  function exportCurrentPlan() {
    const report = createBeforeAfterReport(profileId, selected);
    const blob = new Blob([serializeReport(report)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `hardening-report-${profileId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
      <section className="space-y-4">
        {remediations.map((remediation) => (
          <article key={remediation.id} className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <label className="flex gap-3">
                <input
                  type="checkbox"
                  checked={selected.includes(remediation.id)}
                  onChange={() => toggle(remediation.id)}
                  className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900"
                />
                <span>
                  <span className="block text-lg font-semibold text-white">{remediation.title}</span>
                  <span className="mt-1 block text-sm leading-6 text-slate-400">{remediation.description}</span>
                </span>
              </label>
              <RiskBadge risk={remediation.riskOfBreaking} />
            </div>

            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <div>
                <p className="text-xs font-semibold uppercase text-slate-500">Затрагиваемые файлы</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {remediation.targetFiles.map((file) => (
                    <code key={file} className="rounded-md bg-slate-900 px-2 py-1 text-xs text-slate-300">
                      {file}
                    </code>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="rounded-md bg-slate-900 p-3">
                  <p className="text-slate-500">Резервная копия</p>
                  <p className="mt-1 font-semibold text-white">{remediation.backupRequired ? "Обязательна" : "Журнал действия"}</p>
                </div>
                <div className="rounded-md bg-slate-900 p-3">
                  <p className="text-slate-500">Откат</p>
                  <p className="mt-1 font-semibold text-white">{remediation.rollbackAvailable ? "Доступен" : "Частичный"}</p>
                </div>
              </div>
            </div>

            <ol className="mt-4 grid gap-2 md:grid-cols-2">
              {remediation.demoSteps.map((demoStep) => (
                <li key={demoStep} className="rounded-md border border-slate-800 bg-slate-900/70 px-3 py-2 text-sm text-slate-300">
                  {demoStep}
                </li>
              ))}
            </ol>
            <p className="mt-4 text-sm leading-6 text-slate-400">{remediation.realModeNotes}</p>
          </article>
        ))}
      </section>

      <aside className="h-fit rounded-md border border-slate-800 bg-slate-950/80 p-5 xl:sticky xl:top-8">
          <h2 className="text-lg font-semibold text-white">Демо-применение</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Выбрано действий: {selectedRemediations.length}. В демо-режиме создается отчет и записи резервных копий в памяти браузера.
        </p>

        <div className="mt-5 space-y-3">
          {remediationSteps.map((label, index) => {
            const done = step > index || complete;
            const active = step === index && !complete;
            return (
              <div key={label} className="flex items-center gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3 text-sm">
                {done ? (
                  <CheckCircle2 size={18} className="text-emerald-300" aria-hidden="true" />
                ) : active ? (
                  <Loader2 size={18} className="animate-spin text-sky-300" aria-hidden="true" />
                ) : (
                  <span className="h-[18px] w-[18px] rounded-full border border-slate-600" />
                )}
                {label}
              </div>
            );
          })}
        </div>

        <div className="mt-5 grid gap-3">
          <Button onClick={applyDemo} disabled={!selected.length}>
            <DatabaseBackup size={16} aria-hidden="true" />
            Применить демо
          </Button>
          <Button variant="secondary" onClick={exportCurrentPlan} disabled={!selected.length}>
            <Download size={16} aria-hidden="true" />
            Экспорт JSON
          </Button>
          <LinkButton variant="secondary" href="/reports">
            <ShieldCheck size={16} aria-hidden="true" />
            Открыть отчет
          </LinkButton>
        </div>
      </aside>
    </div>
  );
}
