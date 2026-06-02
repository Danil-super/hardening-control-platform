"use client";

import { CheckCircle2, FileInput, Loader2, Play } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { auditSteps } from "@/lib/demo-audit";
import { Button, LinkButton } from "@/components/ui/button";

export function AuditRunner({ profileId }: { profileId: string }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState(-1);

  function runAudit() {
    setRunning(true);
    setCurrentStep(0);

    auditSteps.forEach((_, index) => {
      window.setTimeout(() => setCurrentStep(index), index * 650);
    });

    window.setTimeout(() => {
      router.push(`/audit/${profileId}/results`);
    }, auditSteps.length * 650 + 450);
  }

  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Процесс демо-аудита</h2>
          <p className="mt-1 text-sm leading-6 text-slate-400">
            Проверки выполняются на демо-данных и не меняют хостовую ОС. Для реального аудита без исправлений используйте
            локальный агент и импорт JSON.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <LinkButton href="/agent/import" variant="secondary">
            <FileInput size={16} aria-hidden="true" />
            Реальный audit-only
          </LinkButton>
          <Button onClick={runAudit} disabled={running}>
            {running ? <Loader2 size={16} className="animate-spin" aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}
            {running ? "Аудит выполняется" : "Запустить демо"}
          </Button>
        </div>
      </div>

      <div className="mt-6 space-y-3">
        {auditSteps.map((step, index) => {
          const done = running && currentStep > index;
          const active = running && currentStep === index;
          return (
            <div key={step} className="flex items-center gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-3">
              {done ? (
                <CheckCircle2 size={18} className="text-emerald-300" aria-hidden="true" />
              ) : active ? (
                <Loader2 size={18} className="animate-spin text-sky-300" aria-hidden="true" />
              ) : (
                <span className="h-[18px] w-[18px] rounded-full border border-slate-600" />
              )}
              <span className={active || done ? "text-slate-100" : "text-slate-500"}>{step}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
