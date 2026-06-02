"use client";

import { Download } from "lucide-react";
import { useEffect, useState } from "react";
import { RiskBadge } from "@/components/ui/badge";
import { Button, LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { createBeforeAfterReport } from "@/lib/demo-audit";
import { getReportDelta, serializeReport } from "@/lib/report-utils";
import type { BeforeAfterReport } from "@/types";

function parseReport(raw: string | null) {
  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as BeforeAfterReport;
  } catch {
    return null;
  }
}

export function ReportsClient() {
  const [report, setReport] = useState<BeforeAfterReport | null>(null);

  useEffect(() => {
    const saved = parseReport(window.localStorage.getItem("hcp:last-report"));
    setReport(saved ?? createBeforeAfterReport("basic_linux", ["disable_ssh_root_login", "enable_ufw"]));
  }, []);

  if (!report) {
    return null;
  }

  const delta = getReportDelta(report);

  function downloadReport() {
    if (!report) {
      return;
    }
    const blob = new Blob([serializeReport(report)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "hardening-before-after-report.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard label="Оценка до" value={`${report.before.summary.score}%`} detail="Исходная оценка защищенности" />
        <SummaryCard label="Оценка после" value={`${report.after.summary.score}%`} detail={`Изменение +${delta.score}`} />
        <SummaryCard label="Исправлено" value={report.fixedFindings.length} detail="Проблемы с примененными действиями" />
        <SummaryCard label="Осталось" value={report.remainingFindings.length} detail="Вручную или не выбрано" />
        <SummaryCard label="Резервные копии" value={report.backups.length} detail="Созданные/пропущенные демо-записи" />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-lg font-semibold text-white">До / после</h2>
          <div className="mt-4 grid grid-cols-4 gap-3 text-sm">
            {(["high", "medium", "low", "info"] as const).map((risk) => (
              <div key={risk} className="rounded-md bg-slate-900 p-3">
                <RiskBadge risk={risk} />
                <p className="mt-3 text-slate-400">до: {report.before.summary[risk]}</p>
                <p className="text-slate-100">после: {report.after.summary[risk]}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-lg font-semibold text-white">Записи резервных копий</h2>
          <div className="mt-4 space-y-3">
            {report.backups.map((backup) => (
              <div key={backup.id} className="rounded-md bg-slate-900 p-3 text-sm">
                <p className="font-semibold text-white">{backup.id}</p>
                <p className="mt-1 text-slate-400">{backup.remediationId} · {backup.status === "created" ? "создана" : "пропущена"}</p>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="grid gap-5 lg:grid-cols-3">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-lg font-semibold text-white">Исправлено</h2>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            {report.fixedFindings.map((finding) => <li key={finding.id}>{finding.title}</li>)}
          </ul>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-lg font-semibold text-white">Осталось</h2>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            {report.remainingFindings.map((finding) => <li key={finding.id}>{finding.title}</li>)}
          </ul>
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-lg font-semibold text-white">Ручная проверка</h2>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            {report.manualFindings.map((finding) => <li key={finding.id}>{finding.title}</li>)}
          </ul>
        </div>
      </section>

      <div className="flex flex-wrap justify-end gap-3">
        <LinkButton variant="secondary" href="/remediation">Изменить remediation</LinkButton>
        <Button onClick={downloadReport}><Download size={16} aria-hidden="true" /> Экспорт JSON</Button>
      </div>
    </div>
  );
}
