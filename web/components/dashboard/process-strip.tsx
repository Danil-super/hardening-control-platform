import { ArrowRight, DatabaseBackup, FileCheck, ListChecks, Radar, ShieldCheck, Wrench } from "lucide-react";

const steps = [
  { label: "аудит", icon: Radar },
  { label: "находки", icon: ListChecks },
  { label: "исправления", icon: Wrench },
  { label: "резервная копия", icon: DatabaseBackup },
  { label: "повторный аудит", icon: ShieldCheck },
  { label: "отчет", icon: FileCheck },
];

export function ProcessStrip() {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-slate-800 bg-slate-950/70 p-3">
      {steps.map((step, index) => {
        const Icon = step.icon;
        return (
          <div key={step.label} className="flex items-center gap-2">
            <span className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-3 py-2 text-sm text-slate-200">
              <Icon size={16} aria-hidden="true" />
              {step.label}
            </span>
            {index < steps.length - 1 ? <ArrowRight size={16} className="text-slate-500" aria-hidden="true" /> : null}
          </div>
        );
      })}
    </div>
  );
}
