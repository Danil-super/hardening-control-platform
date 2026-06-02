"use client";

import {
  CheckCircle2,
  ClipboardList,
  Download,
  FileJson,
  FileText,
  GitCompare,
  History,
  PlugZap,
  RefreshCw,
  ShieldCheck,
  Terminal,
  Trash2,
  Upload,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { RiskBadge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { getRemediationsForFindings } from "@/data/remediations";
import type { Finding, FindingSource, Remediation, RiskLevel } from "@/types";

type AgentReport = {
  auditId?: string;
  id?: string;
  createdAt?: string;
  hostname?: string;
  os?: string;
  profileId?: string;
  mode?: "agent";
  agent?: {
    version?: string;
    safeMode?: boolean;
    remediationEnabled?: boolean;
    user?: string;
    integrations?: {
      lynis?: {
        enabled?: boolean;
        findings?: number;
        reportPath?: string | null;
      };
      openscap?: {
        enabled?: boolean;
        findings?: number;
        contentPath?: string | null;
        profile?: string | null;
      };
    };
  };
  summary?: {
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
    score?: number;
  };
  findings?: Finding[];
};

type StoredAgentReport = {
  key: string;
  label: string;
  importedAt: string;
  report: AgentReport;
};

type SourceFilter = FindingSource | "all";
type BridgeStatus = "idle" | "checking" | "online" | "offline";

type AgentRemediationPlan = {
  generatedAt: string;
  mode: "plan_only";
  auditId?: string;
  hostname?: string;
  os?: string;
  profileId?: string;
  summary: ReturnType<typeof getSummary>;
  safetyNotice: string;
  remediations: Array<{
    id: string;
    title: string;
    riskOfBreaking: Remediation["riskOfBreaking"];
    targetFiles: string[];
    backupRequired: boolean;
    rollbackAvailable: boolean;
    matchedFindingIds: string[];
    steps: string[];
    realModeNotes: string;
  }>;
  manualFindings: Array<{
    id: string;
    title: string;
    risk: RiskLevel;
    status: Finding["status"];
    recommendation: string;
  }>;
};

const historyStorageKey = "hcp:agent-report-history";
const lastReportStorageKey = "hcp:last-agent-report";

const profileOptions = [
  { id: "basic_linux", label: "Базовое усиление Linux" },
  { id: "ssh_security", label: "Безопасность SSH" },
  { id: "web_server", label: "Усиление веб-сервера" },
  { id: "docker_host", label: "Усиление Docker-хоста" },
];

const auditOnlyCommands = [
  {
    label: "Базовый audit-only запуск",
    command: "sudo python3 agent.py audit --profile basic_linux --pretty > ~/Загрузки/agent-report.json",
  },
  {
    label: "С Lynis и OpenSCAP",
    command:
      "sudo python3 agent.py audit --profile basic_linux --include-lynis --include-openscap --pretty > ~/Загрузки/agent-report.json",
  },
  {
    label: "Локальный bridge для сайта",
    command: "cd agent\nsudo python3 server.py",
  },
];

const riskLabels: Record<RiskLevel, string> = {
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
};

const statusLabels: Record<Finding["status"], string> = {
  failed: "Не пройдено",
  passed: "Пройдено",
  fixed: "Исправлено",
  manual: "Требует ручной проверки",
};

const sourceLabels: Record<FindingSource, string> = {
  demo: "Демо",
  agent: "Агент",
  lynis: "Lynis",
  openscap: "OpenSCAP",
  custom: "Пользовательский",
};

const sourceClasses: Record<FindingSource, string> = {
  demo: "border-emerald-400/40 bg-emerald-500/15 text-emerald-100",
  agent: "border-sky-400/40 bg-sky-500/15 text-sky-100",
  lynis: "border-amber-400/40 bg-amber-500/15 text-amber-100",
  openscap: "border-violet-400/40 bg-violet-500/15 text-violet-100",
  custom: "border-slate-400/40 bg-slate-500/15 text-slate-200",
};

function SourceBadge({ source }: { source: FindingSource }) {
  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold uppercase ${sourceClasses[source]}`}>
      {sourceLabels[source]}
    </span>
  );
}

function normalizeReport(payload: unknown): AgentReport {
  if (!payload || typeof payload !== "object") {
    throw new Error("JSON должен быть объектом отчета агента.");
  }

  const report = payload as AgentReport;
  if (!Array.isArray(report.findings)) {
    throw new Error("В JSON не найден массив результатов проверок.");
  }

  return report;
}

function countRisks(findings: Finding[]) {
  return findings.reduce(
    (summary, finding) => {
      if (finding.status !== "passed" && finding.status !== "fixed") {
        summary[finding.risk] += 1;
      }
      return summary;
    },
    { high: 0, medium: 0, low: 0, info: 0 } as Record<RiskLevel, number>,
  );
}

function getReportId(report: AgentReport) {
  return report.auditId ?? report.id ?? `agent_report_${Date.now()}`;
}

function getReportLabel(report: AgentReport) {
  const created = report.createdAt ? new Date(report.createdAt) : null;
  const createdLabel = created && !Number.isNaN(created.getTime()) ? created.toLocaleString("ru-RU") : "без даты";
  return `${report.profileId ?? "unknown"} · ${report.hostname ?? "host"} · ${createdLabel}`;
}

function getSummary(report: AgentReport | null) {
  const findings = report?.findings ?? [];
  const fallback = countRisks(findings);
  return {
    high: report?.summary?.high ?? fallback.high,
    medium: report?.summary?.medium ?? fallback.medium,
    low: report?.summary?.low ?? fallback.low,
    info: report?.summary?.info ?? fallback.info,
    score: report?.summary?.score ?? 0,
  };
}

function getActiveFindingIds(report: AgentReport | null) {
  return new Set(
    (report?.findings ?? [])
      .filter((finding) => finding.status !== "passed" && finding.status !== "fixed")
      .map((finding) => finding.id),
  );
}

function getActiveFindings(report: AgentReport | null) {
  return (report?.findings ?? []).filter((finding) => finding.status !== "passed" && finding.status !== "fixed");
}

function countSources(findings: Finding[]) {
  return findings.reduce((counts, finding) => {
    counts[finding.source] = (counts[finding.source] ?? 0) + 1;
    return counts;
  }, {} as Partial<Record<FindingSource, number>>);
}

function getIntegrationFindingCount(report: AgentReport | null, source: "lynis" | "openscap") {
  const integrationCount = report?.agent?.integrations?.[source]?.findings;
  if (typeof integrationCount === "number") {
    return integrationCount;
  }
  return (report?.findings ?? []).filter((finding) => finding.source === source).length;
}

function buildRemediationPlan(report: AgentReport | null): AgentRemediationPlan | null {
  if (!report) {
    return null;
  }

  const activeFindings = getActiveFindings(report);
  const activeFindingIds = activeFindings.map((finding) => finding.id);
  const plannedRemediations = getRemediationsForFindings(activeFindingIds);
  const plannedFindingIds = new Set(plannedRemediations.flatMap((remediation) => remediation.findingIds));
  const manualFindings = activeFindings.filter(
    (finding) => !finding.remediationAvailable || !plannedFindingIds.has(finding.id),
  );

  return {
    generatedAt: new Date().toISOString(),
    mode: "plan_only",
    auditId: report.auditId ?? report.id,
    hostname: report.hostname,
    os: report.os,
    profileId: report.profileId,
    summary: getSummary(report),
    safetyNotice:
      "План сформирован по отчету агента и не применяет изменения. Перед реальным выполнением нужны резервная копия, проверка доступа и отдельное подтверждение администратора.",
    remediations: plannedRemediations.map((remediation) => ({
      id: remediation.id,
      title: remediation.title,
      riskOfBreaking: remediation.riskOfBreaking,
      targetFiles: remediation.targetFiles,
      backupRequired: remediation.backupRequired,
      rollbackAvailable: remediation.rollbackAvailable,
      matchedFindingIds: remediation.findingIds.filter((findingId) => activeFindingIds.includes(findingId)),
      steps: remediation.demoSteps,
      realModeNotes: remediation.realModeNotes,
    })),
    manualFindings: manualFindings.map((finding) => ({
      id: finding.id,
      title: finding.title,
      risk: finding.risk,
      status: finding.status,
      recommendation: finding.recommendation,
    })),
  };
}

function escapeHtml(value: unknown) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getAuditConclusion(report: AgentReport | null) {
  const summary = getSummary(report);
  if (summary.high > 0) {
    return {
      title: "Обнаружены критичные отклонения",
      text: "Хост требует приоритетного устранения высоких рисков до ввода в промышленную эксплуатацию.",
      tone: "danger",
    };
  }
  if (summary.medium > 0 || summary.score < 80) {
    return {
      title: "Требуется плановое усиление",
      text: "Критичных рисков нет, но остаются настройки, которые нужно проверить вручную или усилить по регламенту.",
      tone: "warning",
    };
  }
  return {
    title: "Профиль в хорошем состоянии",
    text: "По данным текущего аудита хост соответствует базовым требованиям выбранного профиля.",
    tone: "success",
  };
}

function buildHtmlReport(report: AgentReport) {
  const summary = getSummary(report);
  const conclusion = getAuditConclusion(report);
  const generatedAt = new Date().toLocaleString("ru-RU");
  const activeFindings = report.findings?.filter((finding) => finding.status !== "passed" && finding.status !== "fixed") ?? [];
  const passedFindings = report.findings?.filter((finding) => finding.status === "passed" || finding.status === "fixed") ?? [];
  const rows = (report.findings ?? []).map((finding) => `
    <tr>
      <td>
        <strong>${escapeHtml(finding.title)}</strong>
        <p>${escapeHtml(finding.description)}</p>
        <small>${escapeHtml(finding.recommendation)}</small>
      </td>
      <td>${escapeHtml(riskLabels[finding.risk])}</td>
      <td>${escapeHtml(statusLabels[finding.status])}</td>
      <td>${escapeHtml(sourceLabels[finding.source])}</td>
      <td>${escapeHtml(finding.category)}</td>
      <td><code>${escapeHtml(finding.evidence ?? "нет данных")}</code></td>
    </tr>
  `).join("");

  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Отчет аудита ${escapeHtml(report.profileId ?? "agent")}</title>
  <style>
    body { margin: 0; background: #f8fafc; color: #0f172a; font-family: Arial, sans-serif; }
    main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 48px; }
    header { border-bottom: 2px solid #0f172a; padding-bottom: 20px; }
    h1 { margin: 0; font-size: 28px; }
    h2 { margin: 28px 0 12px; font-size: 20px; }
    p { line-height: 1.55; }
    .muted { color: #475569; }
    .grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-top: 18px; }
    .card { background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px; }
    .card span { display: block; color: #64748b; font-size: 12px; text-transform: uppercase; }
    .card strong { display: block; margin-top: 8px; font-size: 24px; }
    .conclusion { border-radius: 8px; padding: 16px; margin-top: 18px; border: 1px solid #cbd5e1; background: #fff; }
    .danger { border-color: #fca5a5; background: #fef2f2; }
    .warning { border-color: #fcd34d; background: #fffbeb; }
    .success { border-color: #86efac; background: #f0fdf4; }
    dl { display: grid; grid-template-columns: 180px 1fr; gap: 8px 16px; }
    dt { color: #64748b; }
    dd { margin: 0; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cbd5e1; }
    th, td { border-bottom: 1px solid #e2e8f0; padding: 10px; text-align: left; vertical-align: top; font-size: 13px; }
    th { background: #e2e8f0; font-size: 12px; text-transform: uppercase; }
    code { white-space: pre-wrap; word-break: break-word; font-family: Consolas, monospace; font-size: 12px; }
    small { color: #334155; }
    @media print { body { background: #fff; } main { padding: 0; } }
    @media (max-width: 820px) { .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } dl { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Отчет аудита защищенности хоста</h1>
      <p class="muted">Сформировано: ${escapeHtml(generatedAt)} · Источник: локальный Linux-агент · Режим: только аудит</p>
    </header>

    <section class="grid">
      <div class="card"><span>Оценка</span><strong>${summary.score}%</strong></div>
      <div class="card"><span>Высокий риск</span><strong>${summary.high}</strong></div>
      <div class="card"><span>Средний риск</span><strong>${summary.medium}</strong></div>
      <div class="card"><span>Низкий риск</span><strong>${summary.low}</strong></div>
      <div class="card"><span>Инфо</span><strong>${summary.info}</strong></div>
    </section>

    <section class="conclusion ${conclusion.tone}">
      <h2>${escapeHtml(conclusion.title)}</h2>
      <p>${escapeHtml(conclusion.text)}</p>
      <p class="muted">Активных результатов с риском: ${activeFindings.length}. Пройдено или исправлено: ${passedFindings.length}.</p>
    </section>

    <section>
      <h2>Параметры аудита</h2>
      <dl>
        <dt>Audit ID</dt><dd>${escapeHtml(report.auditId ?? report.id ?? "не указан")}</dd>
        <dt>Хост</dt><dd>${escapeHtml(report.hostname ?? "не указан")}</dd>
        <dt>ОС</dt><dd>${escapeHtml(report.os ?? "не указана")}</dd>
        <dt>Профиль</dt><dd>${escapeHtml(report.profileId ?? "не указан")}</dd>
        <dt>Версия агента</dt><dd>${escapeHtml(report.agent?.version ?? "не указана")}</dd>
      </dl>
    </section>

    <section>
      <h2>Результаты проверок</h2>
      <table>
        <thead>
          <tr><th>Проблема</th><th>Риск</th><th>Статус</th><th>Источник</th><th>Категория</th><th>Данные проверки</th></tr>
        </thead>
        <tbody>${rows || "<tr><td colspan=\"6\">Результаты проверок отсутствуют.</td></tr>"}</tbody>
      </table>
    </section>
  </main>
</body>
</html>`;
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

export function AgentImportClient() {
  const [endpoint, setEndpoint] = useState("http://127.0.0.1:8765");
  const [profileId, setProfileId] = useState("basic_linux");
  const [includeLynis, setIncludeLynis] = useState(false);
  const [includeOpenScap, setIncludeOpenScap] = useState(false);
  const [rawJson, setRawJson] = useState("");
  const [report, setReport] = useState<AgentReport | null>(null);
  const [history, setHistory] = useState<StoredAgentReport[]>([]);
  const [baselineKey, setBaselineKey] = useState("");
  const [currentKey, setCurrentKey] = useState("");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [bridgeStatus, setBridgeStatus] = useState<BridgeStatus>("idle");
  const [bridgeMessage, setBridgeMessage] = useState("Bridge еще не проверялся.");

  const findings = report?.findings ?? [];
  const filteredFindings = useMemo(
    () => findings.filter((finding) => sourceFilter === "all" || finding.source === sourceFilter),
    [findings, sourceFilter],
  );
  const sourceCounts = useMemo(() => countSources(findings), [findings]);
  const sourceOptions = useMemo(
    () => (Object.keys(sourceCounts) as FindingSource[]).sort((left, right) => left.localeCompare(right)),
    [sourceCounts],
  );
  const summary = useMemo(() => getSummary(report), [report]);
  const remediationPlan = useMemo(() => buildRemediationPlan(report), [report]);
  const baselineReport = history.find((item) => item.key === baselineKey)?.report ?? null;
  const currentReport = history.find((item) => item.key === currentKey)?.report ?? null;
  const comparison = useMemo(() => {
    if (!baselineReport || !currentReport) {
      return null;
    }

    const before = getSummary(baselineReport);
    const after = getSummary(currentReport);
    const beforeActive = getActiveFindingIds(baselineReport);
    const afterActive = getActiveFindingIds(currentReport);
    const fixed = [...beforeActive].filter((id) => !afterActive.has(id));
    const newFindings = [...afterActive].filter((id) => !beforeActive.has(id));

    return {
      before,
      after,
      delta: {
        score: after.score - before.score,
        high: after.high - before.high,
        medium: after.medium - before.medium,
        low: after.low - before.low,
        info: after.info - before.info,
      },
      fixed,
      newFindings,
    };
  }, [baselineReport, currentReport]);

  useEffect(() => {
    try {
      const savedHistory = JSON.parse(window.localStorage.getItem(historyStorageKey) ?? "[]") as StoredAgentReport[];
      setHistory(savedHistory);
      if (savedHistory[0]) {
        setCurrentKey(savedHistory[0].key);
        setReport(savedHistory[0].report);
        setRawJson(JSON.stringify(savedHistory[0].report, null, 2));
      }
      if (savedHistory[1]) {
        setBaselineKey(savedHistory[1].key);
      }
    } catch {
      setHistory([]);
    }
  }, []);

  function saveHistory(nextHistory: StoredAgentReport[]) {
    setHistory(nextHistory);
    window.localStorage.setItem(historyStorageKey, JSON.stringify(nextHistory));
  }

  function loadPayload(payload: unknown) {
    const normalized = normalizeReport(payload);
    const importedAt = new Date().toISOString();
    const key = `${getReportId(normalized)}_${importedAt}`;
    const item: StoredAgentReport = {
      key,
      label: getReportLabel(normalized),
      importedAt,
      report: normalized,
    };
    const nextHistory = [item, ...history.filter((entry) => getReportId(entry.report) !== getReportId(normalized))].slice(0, 12);
    saveHistory(nextHistory);
    setReport(normalized);
    setCurrentKey(key);
    setSourceFilter("all");
    if (!baselineKey && nextHistory[1]) {
      setBaselineKey(nextHistory[1].key);
    }
    setRawJson(JSON.stringify(normalized, null, 2));
    setError("");
    window.localStorage.setItem(lastReportStorageKey, JSON.stringify(normalized));
  }

  async function checkBridgeHealth() {
    setBridgeStatus("checking");
    setBridgeMessage("Проверяем локальный bridge...");
    try {
      const base = endpoint.replace(/\/$/, "");
      const response = await fetch(`${base}/health`, {
        method: "GET",
        headers: { Accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      const version = typeof payload?.version === "string" ? `, версия ${payload.version}` : "";
      setBridgeStatus("online");
      setBridgeMessage(`Bridge доступен: ${payload?.service ?? "hcp-agent-bridge"}${version}.`);
    } catch (event) {
      const message = event instanceof Error ? event.message : "неизвестная ошибка";
      setBridgeStatus("offline");
      setBridgeMessage(`Bridge недоступен: ${message}. Запустите python3 server.py в папке agent.`);
    }
  }

  async function fetchFromLocalAgent() {
    setLoading(true);
    setError("");
    try {
      const base = endpoint.replace(/\/$/, "");
      const params = new URLSearchParams({ profile: profileId });
      if (includeLynis) {
        params.set("includeLynis", "1");
      }
      if (includeOpenScap) {
        params.set("includeOpenScap", "1");
      }
      const response = await fetch(
        `${base}/audit?${params.toString()}`,
        {
          method: "GET",
          headers: { Accept: "application/json" },
        },
      );

      if (!response.ok) {
        throw new Error(`Локальный агент вернул HTTP ${response.status}`);
      }

      loadPayload(await response.json());
    } catch (event) {
      const message = event instanceof Error ? event.message : "Не удалось получить отчет от локального агента.";
      setError(`${message}. Проверьте, что agent bridge запущен и доступен по указанному адресу.`);
    } finally {
      setLoading(false);
    }
  }

  function importFromText() {
    try {
      loadPayload(JSON.parse(rawJson));
    } catch (event) {
      setError(event instanceof Error ? event.message : "Не удалось разобрать JSON.");
    }
  }

  function importFromFile(file: File | null) {
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const content = String(reader.result ?? "");
        setRawJson(content);
        loadPayload(JSON.parse(content));
      } catch (event) {
        setError(event instanceof Error ? event.message : "Не удалось импортировать файл.");
      }
    };
    reader.readAsText(file);
  }

  function downloadImportedReport() {
    if (!report) {
      return;
    }
    downloadBlob(JSON.stringify(report, null, 2), `agent-report-${report.profileId ?? "audit"}.json`, "application/json");
  }

  function downloadAuditHtmlReport() {
    if (!report) {
      return;
    }
    downloadBlob(buildHtmlReport(report), `agent-report-${report.profileId ?? "audit"}.html`, "text/html;charset=utf-8");
  }

  function downloadRemediationPlan() {
    if (!remediationPlan) {
      return;
    }
    downloadBlob(
      JSON.stringify(remediationPlan, null, 2),
      `agent-remediation-plan-${remediationPlan.profileId ?? "audit"}.json`,
      "application/json",
    );
  }

  function loadFromHistory(key: string) {
    const item = history.find((entry) => entry.key === key);
    if (!item) {
      return;
    }
    setReport(item.report);
    setCurrentKey(key);
    setRawJson(JSON.stringify(item.report, null, 2));
    setSourceFilter("all");
    setError("");
  }

  function clearHistory() {
    saveHistory([]);
    setBaselineKey("");
    setCurrentKey("");
    setReport(null);
    setRawJson("");
    setSourceFilter("all");
    window.localStorage.removeItem(lastReportStorageKey);
  }

  return (
    <div className="space-y-6">
      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="rounded-md border border-sky-400/25 bg-sky-500/10 p-5">
          <div className="flex items-center gap-3">
            <ShieldCheck size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Аудит системы без исправления</h2>
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-300">
            Команда `audit` только читает конфигурации, запускает безопасные проверки и возвращает JSON. Она не меняет
            файлы, не включает firewall, не перезапускает службы и не применяет remediation.
          </p>
          <div className="mt-4 grid gap-3">
            {auditOnlyCommands.map((item) => (
              <div key={item.label} className="rounded-md border border-slate-800 bg-slate-950/70 p-3">
                <p className="text-xs font-semibold uppercase text-slate-500">{item.label}</p>
                <code className="mt-2 block whitespace-pre-wrap break-words rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
                  {item.command}
                </code>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <Terminal size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Готовность источников аудита</h2>
          </div>
          <div className="mt-4 space-y-3 text-sm">
            <div className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-3">
              <p className="font-semibold text-emerald-100">Базовый агент</p>
              <p className="mt-1 leading-6 text-emerald-100/80">
                Всегда включен. Проверяет SSH, UFW, обновления, fail2ban, Nginx и Docker в audit-only режиме.
              </p>
            </div>
            <div className={`rounded-md border p-3 ${
              includeLynis ? "border-amber-400/30 bg-amber-500/10" : "border-slate-800 bg-slate-900/70"
            }`}>
              <p className={includeLynis ? "font-semibold text-amber-100" : "font-semibold text-slate-200"}>Lynis</p>
              <p className={includeLynis ? "mt-1 leading-6 text-amber-100/80" : "mt-1 leading-6 text-slate-400"}>
                {includeLynis ? "Будет запрошен при следующем аудите." : "Выключен. Включите переключатель ниже, если Lynis установлен."}
              </p>
            </div>
            <div className={`rounded-md border p-3 ${
              includeOpenScap ? "border-violet-400/30 bg-violet-500/10" : "border-slate-800 bg-slate-900/70"
            }`}>
              <p className={includeOpenScap ? "font-semibold text-violet-100" : "font-semibold text-slate-200"}>
                OpenSCAP / SCAP Security Guide
              </p>
              <p className={includeOpenScap ? "mt-1 leading-6 text-violet-100/80" : "mt-1 leading-6 text-slate-400"}>
                {includeOpenScap
                  ? "Будет запрошен при следующем аудите."
                  : "Выключен. Для работы нужны openscap-scanner и SCAP Security Guide."}
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <PlugZap size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Автоматический импорт через локальный агент</h2>
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Запустите `python3 server.py` в папке `agent`, затем нажмите кнопку ниже. Сайт запросит JSON у локального
            промежуточного сервера и покажет реальные результаты проверок.
          </p>

          <div className="mt-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_260px]">
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Адрес agent bridge</span>
              <input
                value={endpoint}
                onChange={(event) => setEndpoint(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Профиль</span>
              <select
                value={profileId}
                onChange={(event) => setProfileId(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                {profileOptions.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className={`mt-4 rounded-md border p-4 text-sm ${
            bridgeStatus === "online"
              ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100"
              : bridgeStatus === "offline"
                ? "border-red-400/30 bg-red-500/10 text-red-100"
                : "border-slate-800 bg-slate-900/70 text-slate-300"
          }`}>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3">
                <CheckCircle2 size={18} className="mt-0.5 shrink-0" aria-hidden="true" />
                <p className="leading-6">{bridgeMessage}</p>
              </div>
              <Button variant="secondary" onClick={checkBridgeHealth} disabled={bridgeStatus === "checking"}>
                <RefreshCw size={16} className={bridgeStatus === "checking" ? "animate-spin" : ""} aria-hidden="true" />
                Проверить bridge
              </Button>
            </div>
          </div>

          <label className="mt-4 flex items-start gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={includeLynis}
              onChange={(event) => setIncludeLynis(event.target.checked)}
              className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            <span>
              <span className="block font-semibold text-white">Включить расширенный аудит Lynis</span>
              <span className="mt-1 block leading-6 text-slate-400">
                Агент попробует запустить Lynis на локальном хосте и добавить найденные предупреждения в отчет.
                Если Lynis не установлен, отчет останется валидным и покажет отдельную рекомендацию.
              </span>
            </span>
          </label>

          <label className="mt-3 flex items-start gap-3 rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={includeOpenScap}
              onChange={(event) => setIncludeOpenScap(event.target.checked)}
              className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-950"
            />
            <span>
              <span className="block font-semibold text-white">Включить аудит OpenSCAP / SCAP Security Guide</span>
              <span className="mt-1 block leading-6 text-slate-400">
                Агент попробует запустить `oscap xccdf eval`, разобрать XML-результаты и добавить несоответствия
                как отдельный источник OpenSCAP. Если OpenSCAP или datastream SSG не найдены, отчет останется валидным.
              </span>
            </span>
          </label>

          <Button onClick={fetchFromLocalAgent} disabled={loading} className="mt-5">
            <PlugZap size={16} aria-hidden="true" />
            {loading ? "Запрос выполняется..." : "Получить аудит от агента"}
          </Button>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <FileJson size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Ручной импорт JSON</h2>
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Если автоматический запрос недоступен, сохраните вывод агента в файл или вставьте JSON вручную.
          </p>

          <label className="mt-5 flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-slate-700 bg-slate-900 px-4 py-5 text-sm text-slate-300 transition hover:border-sky-300 hover:text-white">
            <Upload size={16} aria-hidden="true" />
            Загрузить JSON-файл
            <input
              type="file"
              accept="application/json,.json"
              onChange={(event) => importFromFile(event.target.files?.[0] ?? null)}
              className="hidden"
            />
          </label>
        </div>
      </section>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <h2 className="text-xl font-semibold text-white">Вставить JSON вручную</h2>
        <textarea
          value={rawJson}
          onChange={(event) => setRawJson(event.target.value)}
          rows={10}
          className="mt-4 w-full rounded-md border border-slate-700 bg-slate-900 p-3 font-mono text-sm text-slate-100"
          placeholder='{"auditId":"agent_audit_basic_linux_...","findings":[]}'
        />
        <div className="mt-4 flex flex-wrap gap-3">
          <Button onClick={importFromText}>
            <FileJson size={16} aria-hidden="true" />
            Импортировать JSON
          </Button>
          <Button variant="secondary" onClick={downloadImportedReport} disabled={!report}>
            <Download size={16} aria-hidden="true" />
            Скачать текущий отчет
          </Button>
          <Button variant="secondary" onClick={downloadAuditHtmlReport} disabled={!report}>
            <FileText size={16} aria-hidden="true" />
            Скачать HTML-отчет
          </Button>
          <Button variant="secondary" onClick={downloadRemediationPlan} disabled={!remediationPlan}>
            <ClipboardList size={16} aria-hidden="true" />
            Скачать план исправлений
          </Button>
        </div>
        {error ? (
          <div className="mt-4 rounded-md border border-red-400/40 bg-red-500/15 p-4 text-sm leading-6 text-red-100">
            {error}
          </div>
        ) : null}
      </section>

      {report ? (
        <section className="space-y-5">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <SummaryCard label="Оценка" value={`${summary.score}%`} detail="По данным агента" />
            <SummaryCard label="Высокий" value={summary.high} detail="Активные риски" />
            <SummaryCard label="Средний" value={summary.medium} detail="Плановая проверка" />
            <SummaryCard label="Низкий" value={summary.low} detail="Улучшения" />
            <SummaryCard label="Инфо" value={summary.info} detail="Контекст" />
          </div>

          <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
            <div className="flex items-center gap-3">
              <ShieldCheck size={22} className="text-sky-200" aria-hidden="true" />
              <h2 className="text-xl font-semibold text-white">Что проверено в этом аудите</h2>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-3">
              <div className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-4">
                <p className="font-semibold text-emerald-100">Базовый агент</p>
                <p className="mt-2 text-2xl font-semibold text-white">{sourceCounts.agent ?? 0}</p>
                <p className="mt-1 text-sm leading-6 text-emerald-100/80">локальных проверок и системных сигналов</p>
              </div>
              <div className="rounded-md border border-amber-400/30 bg-amber-500/10 p-4">
                <p className="font-semibold text-amber-100">Lynis</p>
                <p className="mt-2 text-2xl font-semibold text-white">{getIntegrationFindingCount(report, "lynis")}</p>
                <p className="mt-1 text-sm leading-6 text-amber-100/80">
                  {report.agent?.integrations?.lynis?.enabled ? "источник был включен" : "источник не был включен в этом запуске"}
                </p>
              </div>
              <div className="rounded-md border border-violet-400/30 bg-violet-500/10 p-4">
                <p className="font-semibold text-violet-100">OpenSCAP</p>
                <p className="mt-2 text-2xl font-semibold text-white">{getIntegrationFindingCount(report, "openscap")}</p>
                <p className="mt-1 text-sm leading-6 text-violet-100/80">
                  {report.agent?.integrations?.openscap?.enabled ? "источник был включен" : "источник не был включен в этом запуске"}
                </p>
              </div>
            </div>
            <p className="mt-4 text-sm leading-6 text-slate-400">
              Если Lynis или OpenSCAP включены, но инструмент не установлен, отчет остается валидным и содержит отдельную
              диагностическую находку вроде `lynis_not_installed` или `openscap_not_installed`.
            </p>
          </div>

          <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <h2 className="text-xl font-semibold text-white">Источники результатов</h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Разделение показывает, какие проверки выполнены базовым агентом, а какие пришли из внешних сканеров.
                </p>
              </div>
              <label className="block min-w-[220px]">
                <span className="text-xs font-semibold uppercase text-slate-500">Фильтр источника</span>
                <select
                  value={sourceFilter}
                  onChange={(event) => setSourceFilter(event.target.value as SourceFilter)}
                  className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
                >
                  <option value="all">Все источники</option>
                  {sourceOptions.map((source) => (
                    <option key={source} value={source}>
                      {sourceLabels[source]} ({sourceCounts[source] ?? 0})
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              {sourceOptions.length ? sourceOptions.map((source) => (
                <div key={source} className="rounded-md border border-slate-800 bg-slate-900/70 p-3">
                  <SourceBadge source={source} />
                  <p className="mt-3 text-2xl font-semibold text-white">{sourceCounts[source] ?? 0}</p>
                  <p className="mt-1 text-xs text-slate-500">результатов проверки</p>
                </div>
              )) : (
                <p className="rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
                  Источники появятся после импорта отчета.
                </p>
              )}
            </div>
          </div>

          <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h2 className="text-xl font-semibold text-white">Отчет агента</h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">{getAuditConclusion(report).text}</p>
              </div>
              <span className={`rounded-md border px-3 py-2 text-sm font-semibold ${
                getAuditConclusion(report).tone === "danger"
                  ? "border-red-400/40 bg-red-500/15 text-red-100"
                  : getAuditConclusion(report).tone === "warning"
                    ? "border-amber-400/40 bg-amber-500/15 text-amber-100"
                    : "border-emerald-400/40 bg-emerald-500/15 text-emerald-100"
              }`}>
                {getAuditConclusion(report).title}
              </span>
            </div>
            <div className="mt-4 grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-md bg-slate-900 p-3">
                <p className="text-slate-500">Audit ID</p>
                <p className="mt-1 break-all font-semibold text-white">{report.auditId ?? report.id}</p>
              </div>
              <div className="rounded-md bg-slate-900 p-3">
                <p className="text-slate-500">Хост</p>
                <p className="mt-1 font-semibold text-white">{report.hostname ?? "не указан"}</p>
              </div>
              <div className="rounded-md bg-slate-900 p-3">
                <p className="text-slate-500">ОС</p>
                <p className="mt-1 font-semibold text-white">{report.os ?? "не указана"}</p>
              </div>
              <div className="rounded-md bg-slate-900 p-3">
                <p className="text-slate-500">Профиль</p>
                <p className="mt-1 font-semibold text-white">{report.profileId ?? "не указан"}</p>
              </div>
            </div>
          </div>

          {remediationPlan ? (
            <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <div className="flex items-center gap-3">
                    <ClipboardList size={22} className="text-sky-200" aria-hidden="true" />
                    <h2 className="text-xl font-semibold text-white">План исправлений по отчету агента</h2>
                  </div>
                  <p className="mt-3 max-w-4xl text-sm leading-6 text-slate-400">
                    План не применяет изменения. Он связывает активные результаты проверок с известными действиями,
                    показывает риск изменения, затрагиваемые файлы, необходимость резервной копии и доступность отката.
                  </p>
                </div>
                <Button variant="secondary" onClick={downloadRemediationPlan}>
                  <Download size={16} aria-hidden="true" />
                  JSON-план
                </Button>
              </div>

              <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
                <div className="space-y-3">
                  {remediationPlan.remediations.length ? remediationPlan.remediations.map((remediation) => (
                    <article key={remediation.id} className="rounded-md border border-slate-800 bg-slate-900/70 p-4">
                      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                        <div>
                          <h3 className="font-semibold text-white">{remediation.title}</h3>
                          <p className="mt-1 text-sm leading-6 text-slate-400">{remediation.realModeNotes}</p>
                        </div>
                        <RiskBadge risk={remediation.riskOfBreaking} />
                      </div>
                      <div className="mt-4 grid gap-3 text-sm md:grid-cols-2">
                        <div className="rounded-md bg-slate-950/70 p-3">
                          <p className="text-slate-500">Резервная копия</p>
                          <p className="mt-1 font-semibold text-white">{remediation.backupRequired ? "обязательна" : "не обязательна"}</p>
                        </div>
                        <div className="rounded-md bg-slate-950/70 p-3">
                          <p className="text-slate-500">Откат</p>
                          <p className="mt-1 font-semibold text-white">{remediation.rollbackAvailable ? "доступен" : "частичный или ручной"}</p>
                        </div>
                      </div>
                      <div className="mt-4">
                        <p className="text-xs font-semibold uppercase text-slate-500">Затрагиваемые файлы</p>
                        <div className="mt-2 flex flex-wrap gap-2">
                          {remediation.targetFiles.map((file) => (
                            <code key={file} className="rounded-md bg-slate-950 px-2 py-1 text-xs text-slate-300">{file}</code>
                          ))}
                        </div>
                      </div>
                      <ol className="mt-4 grid gap-2 md:grid-cols-2">
                        {remediation.steps.map((step) => (
                          <li key={step} className="rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-300">
                            {step}
                          </li>
                        ))}
                      </ol>
                    </article>
                  )) : (
                    <p className="rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
                      Для активных результатов не найдено автоматизированных действий. Используйте ручные рекомендации ниже.
                    </p>
                  )}
                </div>

                <aside className="h-fit rounded-md border border-amber-400/30 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
                  <p className="font-semibold">Ручная проверка: {remediationPlan.manualFindings.length}</p>
                  <ul className="mt-3 space-y-2">
                    {remediationPlan.manualFindings.length ? remediationPlan.manualFindings.map((finding) => (
                      <li key={finding.id}>
                        <span className="font-semibold">{finding.title}</span>
                        <span className="block text-amber-100/80">{finding.recommendation}</span>
                      </li>
                    )) : (
                      <li>Все активные результаты сопоставлены с известными действиями.</li>
                    )}
                  </ul>
                </aside>
              </div>
            </div>
          ) : null}

          <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1040px] border-collapse text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Проблема</th>
                    <th className="px-4 py-3">Источник</th>
                    <th className="px-4 py-3">Риск</th>
                    <th className="px-4 py-3">Статус</th>
                    <th className="px-4 py-3">Категория</th>
                    <th className="px-4 py-3">Данные проверки</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((finding) => (
                    <tr key={finding.id} className="border-b border-slate-900 align-top last:border-b-0">
                      <td className="px-4 py-4">
                        <p className="font-semibold text-white">{finding.title}</p>
                        <p className="mt-1 max-w-xl leading-6 text-slate-400">{finding.description}</p>
                        <p className="mt-2 text-slate-300">{finding.recommendation}</p>
                      </td>
                      <td className="px-4 py-4"><SourceBadge source={finding.source} /></td>
                      <td className="px-4 py-4"><RiskBadge risk={finding.risk} /></td>
                      <td className="px-4 py-4"><StatusBadge status={finding.status} /></td>
                      <td className="px-4 py-4 text-slate-300">{finding.category}</td>
                      <td className="px-4 py-4">
                        <code className="whitespace-pre-wrap break-words rounded-md bg-slate-900 px-2 py-1 text-xs text-slate-300">
                          {finding.evidence ?? "нет данных"}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!filteredFindings.length ? (
                <div className="border-t border-slate-800 p-5 text-sm text-slate-400">
                  Для выбранного источника результатов нет.
                </div>
              ) : null}
            </div>
          </div>
        </section>
      ) : null}

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <History size={22} className="text-sky-200" aria-hidden="true" />
              <h2 className="text-xl font-semibold text-white">История импортов</h2>
            </div>
            <Button variant="secondary" onClick={clearHistory} disabled={!history.length}>
              <Trash2 size={16} aria-hidden="true" />
              Очистить
            </Button>
          </div>

          <div className="mt-5 space-y-3">
            {history.length ? history.map((item) => {
              const itemSummary = getSummary(item.report);
              return (
                <button
                  key={item.key}
                  onClick={() => loadFromHistory(item.key)}
                  className={`w-full rounded-md border p-4 text-left transition ${
                    currentKey === item.key
                      ? "border-sky-300 bg-sky-400/10"
                      : "border-slate-800 bg-slate-900/70 hover:border-slate-600"
                  }`}
                >
                  <span className="block text-sm font-semibold text-white">{item.label}</span>
                  <span className="mt-1 block text-xs text-slate-500">
                    Импорт: {new Date(item.importedAt).toLocaleString("ru-RU")} · Оценка {itemSummary.score}% · высокий:{itemSummary.high} средний:{itemSummary.medium} низкий:{itemSummary.low} инфо:{itemSummary.info}
                  </span>
                </button>
              );
            }) : (
              <p className="rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
                История появится после первого автоматического или ручного импорта.
              </p>
            )}
          </div>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <GitCompare size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Сравнение отчетов</h2>
          </div>

          <div className="mt-5 space-y-3">
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Базовый отчет</span>
              <select
                value={baselineKey}
                onChange={(event) => setBaselineKey(event.target.value)}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                <option value="">Выберите отчет</option>
                {history.map((item) => (
                  <option key={item.key} value={item.key}>{item.label}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase text-slate-500">Текущий отчет</span>
              <select
                value={currentKey}
                onChange={(event) => {
                  setCurrentKey(event.target.value);
                  loadFromHistory(event.target.value);
                }}
                className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
              >
                <option value="">Выберите отчет</option>
                {history.map((item) => (
                  <option key={item.key} value={item.key}>{item.label}</option>
                ))}
              </select>
            </label>
          </div>

          {comparison ? (
            <div className="mt-5 space-y-4">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="rounded-md bg-slate-900 p-3">
                  <p className="text-slate-500">Оценка до</p>
                  <p className="mt-1 text-2xl font-semibold text-white">{comparison.before.score}%</p>
                </div>
                <div className="rounded-md bg-slate-900 p-3">
                  <p className="text-slate-500">Оценка после</p>
                  <p className="mt-1 text-2xl font-semibold text-white">
                    {comparison.after.score}%{" "}
                    <span className={comparison.delta.score >= 0 ? "text-emerald-200" : "text-red-200"}>
                      ({comparison.delta.score >= 0 ? "+" : ""}{comparison.delta.score})
                    </span>
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-2 text-xs">
                {(["high", "medium", "low", "info"] as const).map((risk) => (
                  <div key={risk} className="rounded-md bg-slate-900 p-3">
                    <RiskBadge risk={risk} />
                    <p className="mt-2 text-slate-400">до: {comparison.before[risk]}</p>
                    <p className="text-slate-100">после: {comparison.after[risk]}</p>
                    <p className={comparison.delta[risk] <= 0 ? "text-emerald-200" : "text-red-200"}>
                      {comparison.delta[risk] >= 0 ? "+" : ""}{comparison.delta[risk]}
                    </p>
                  </div>
                ))}
              </div>

              <div className="grid gap-3 text-sm md:grid-cols-2">
                <div className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-3 text-emerald-100">
                  Исправлено/ушло из активных: {comparison.fixed.length}
                </div>
                <div className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-red-100">
                  Новые активные результаты: {comparison.newFindings.length}
                </div>
              </div>
            </div>
          ) : (
            <p className="mt-5 rounded-md border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-400">
              Импортируйте минимум два отчета и выберите их для сравнения.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
