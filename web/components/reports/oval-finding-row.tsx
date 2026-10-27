"use client";

import { useState } from "react";
import { RiskBadge } from "@/components/ui/badge";
import { FindingDescription } from "@/components/reports/finding-description";
import type { Finding } from "@/types";

export function OvalFindingRow({ finding, reportId }: { finding: Finding; reportId: string }) {
  const [expanded, setExpanded] = useState(false);
  return <details className="group p-4" onToggle={(event) => { if (event.target === event.currentTarget) setExpanded(event.currentTarget.open); }}>
    <summary className="flex cursor-pointer list-none flex-col gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 sm:flex-row sm:items-center sm:justify-between [&::-webkit-details-marker]:hidden">
      <span className="flex min-w-0 items-start gap-3"><span className="text-sky-200 group-open:rotate-90" aria-hidden="true">›</span><span className="break-words text-sm font-medium text-slate-100">{finding.title}</span></span>
      <span className="shrink-0">{finding.severityAssessment?.level === "critical" && !finding.severityUnknown ? <span className="inline-flex rounded-md border border-red-400/50 bg-red-500/20 px-2 py-1 text-xs font-semibold uppercase text-red-100">Критический</span> : <RiskBadge risk={finding.risk} unknown={finding.severityUnknown} />}</span>
    </summary>
    <div className="mt-4 min-w-0 space-y-3 break-words pl-5 text-sm leading-6">
      <FindingDescription original={finding.description} reportId={reportId} findingId={finding.id} expanded={expanded} />
      <p className="text-slate-400">{finding.severityAssessment?.source === "chromium_description" ? "Критичность: оценка разработчика Chromium, явно указанная в описании OVAL. Это не оценка CVSS или отдельная оценка Astra." : finding.severityAssessment?.source === "oval_metadata" ? "Критичность: поле severity в метаданных OVAL." : "Источник не содержит распознанной оценки критичности. Это не означает низкий риск или отсутствие уязвимости."}</p>
      <p className="break-all text-xs text-slate-500">Определение: {finding.id} · OpenSCAP / OVAL · условия уязвимости выполнены</p>
      {finding.evidence ? <details><summary className="cursor-pointer text-sky-200">Технические данные</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-900 p-3 text-xs text-slate-300">{finding.evidence}</pre></details> : null}
    </div>
  </details>;
}
