"use client";

import { Download, FileText } from "lucide-react";
import { useEffect, useState } from "react";
import { RiskBadge } from "@/components/ui/badge";
import { Button, LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { createBeforeAfterReport } from "@/lib/demo-audit";
import { getReportDelta, serializeReport } from "@/lib/report-utils";
import type { BeforeAfterReport } from "@/types";

const riskLabels = {
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
} as const;

function escapeHtml(value: unknown) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function downloadBlob(content: string, filename: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

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

function buildDemoHtmlReport(report: BeforeAfterReport) {
  const delta = getReportDelta(report);
  const generatedAt = new Date().toLocaleString("ru-RU");
  const riskRows = (["high", "medium", "low", "info"] as const).map((risk) => `
    <tr>
      <td>${escapeHtml(riskLabels[risk])}</td>
      <td>${report.before.summary[risk]}</td>
      <td>${report.after.summary[risk]}</td>
      <td>${report.after.summary[risk] - report.before.summary[risk]}</td>
    </tr>
  `).join("");
  const listItems = (items: { id: string; title: string }[]) =>
    items.length ? items.map((item) => `<li>${escapeHtml(item.title)}</li>`).join("") : "<li>Нет записей</li>";
  const backupRows = report.backups.map((backup) => `
    <tr>
      <td>${escapeHtml(backup.id)}</td>
      <td>${escapeHtml(backup.remediationId)}</td>
      <td>${backup.status === "created" ? "создана" : "пропущена"}</td>
      <td>${backup.rollbackAvailable ? "доступен" : "частичный"}</td>
    </tr>
  `).join("");

  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Демо-отчет до/после</title>
  <style>
    body { margin: 0; background: #f8fafc; color: #0f172a; font-family: Arial, sans-serif; }
    main { max-width: 1080px; margin: 0 auto; padding: 32px 20px 48px; }
    header { border-bottom: 2px solid #0f172a; padding-bottom: 20px; }
    h1 { margin: 0; font-size: 28px; }
    h2 { margin: 28px 0 12px; font-size: 20px; }
    p { line-height: 1.55; }
    .muted { color: #475569; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 18px; }
    .card { background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px; }
    .card span { display: block; color: #64748b; font-size: 12px; text-transform: uppercase; }
    .card strong { display: block; margin-top: 8px; font-size: 24px; }
    .notice { border: 1px solid #86efac; background: #f0fdf4; border-radius: 8px; padding: 16px; margin-top: 18px; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cbd5e1; }
    th, td { border-bottom: 1px solid #e2e8f0; padding: 10px; text-align: left; font-size: 13px; }
    th { background: #e2e8f0; font-size: 12px; text-transform: uppercase; }
    .columns { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
    .panel { background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; }
    li { margin: 8px 0; }
    @media print { body { background: #fff; } main { padding: 0; } }
    @media (max-width: 820px) { .grid, .columns { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Демо-отчет по харденингу “до/после”</h1>
      <p class="muted">Сформировано: ${escapeHtml(generatedAt)} · Источник: демонстрационный сценарий платформы</p>
    </header>

    <section class="grid">
      <div class="card"><span>Оценка до</span><strong>${report.before.summary.score}%</strong></div>
      <div class="card"><span>Оценка после</span><strong>${report.after.summary.score}%</strong></div>
      <div class="card"><span>Изменение</span><strong>${delta.score >= 0 ? "+" : ""}${delta.score}</strong></div>
      <div class="card"><span>Исправлено</span><strong>${report.fixedFindings.length}</strong></div>
    </section>

    <section class="notice">
      <h2>Заключение</h2>
      <p>Демонстрационный сценарий показывает полный цикл управления харденингом: выбор исправлений, имитацию резервных копий, повторный аудит и сравнение результата.</p>
    </section>

    <section>
      <h2>Изменение рисков</h2>
      <table>
        <thead><tr><th>Риск</th><th>До</th><th>После</th><th>Изменение</th></tr></thead>
        <tbody>${riskRows}</tbody>
      </table>
    </section>

    <section class="columns">
      <div class="panel"><h2>Исправлено</h2><ul>${listItems(report.fixedFindings)}</ul></div>
      <div class="panel"><h2>Осталось</h2><ul>${listItems(report.remainingFindings)}</ul></div>
      <div class="panel"><h2>Ручная проверка</h2><ul>${listItems(report.manualFindings)}</ul></div>
    </section>

    <section>
      <h2>Резервные копии</h2>
      <table>
        <thead><tr><th>ID</th><th>Исправление</th><th>Статус</th><th>Откат</th></tr></thead>
        <tbody>${backupRows || "<tr><td colspan=\"4\">Записи отсутствуют.</td></tr>"}</tbody>
      </table>
    </section>
  </main>
</body>
</html>`;
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
    downloadBlob(serializeReport(report), "hardening-before-after-report.json", "application/json");
  }

  function downloadHtmlReport() {
    if (!report) {
      return;
    }
    downloadBlob(buildDemoHtmlReport(report), "hardening-before-after-report.html", "text/html;charset=utf-8");
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
        <LinkButton variant="secondary" href="/remediation">Изменить исправления</LinkButton>
        <Button variant="secondary" onClick={downloadHtmlReport}><FileText size={16} aria-hidden="true" /> Экспорт HTML</Button>
        <Button onClick={downloadReport}><Download size={16} aria-hidden="true" /> Экспорт JSON</Button>
      </div>
    </div>
  );
}
