"use client";

import { Download, FileJson, PlugZap, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { RiskBadge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import type { Finding, RiskLevel } from "@/types";

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

const profileOptions = [
  { id: "basic_linux", label: "Базовое усиление Linux" },
  { id: "ssh_security", label: "Безопасность SSH" },
  { id: "web_server", label: "Усиление веб-сервера" },
  { id: "docker_host", label: "Усиление Docker-хоста" },
];

function normalizeReport(payload: unknown): AgentReport {
  if (!payload || typeof payload !== "object") {
    throw new Error("JSON должен быть объектом отчета агента.");
  }

  const report = payload as AgentReport;
  if (!Array.isArray(report.findings)) {
    throw new Error("В JSON не найден массив findings.");
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

export function AgentImportClient() {
  const [endpoint, setEndpoint] = useState("http://127.0.0.1:8765");
  const [profileId, setProfileId] = useState("basic_linux");
  const [rawJson, setRawJson] = useState("");
  const [report, setReport] = useState<AgentReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const findings = report?.findings ?? [];
  const fallbackSummary = useMemo(() => countRisks(findings), [findings]);
  const summary = {
    high: report?.summary?.high ?? fallbackSummary.high,
    medium: report?.summary?.medium ?? fallbackSummary.medium,
    low: report?.summary?.low ?? fallbackSummary.low,
    info: report?.summary?.info ?? fallbackSummary.info,
    score: report?.summary?.score ?? 0,
  };

  function loadPayload(payload: unknown) {
    const normalized = normalizeReport(payload);
    setReport(normalized);
    setRawJson(JSON.stringify(normalized, null, 2));
    setError("");
    window.localStorage.setItem("hcp:last-agent-report", JSON.stringify(normalized));
  }

  async function fetchFromLocalAgent() {
    setLoading(true);
    setError("");
    try {
      const base = endpoint.replace(/\/$/, "");
      const response = await fetch(`${base}/audit?profile=${encodeURIComponent(profileId)}`, {
        method: "GET",
        headers: { Accept: "application/json" },
      });

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
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `agent-report-${report.profileId ?? "audit"}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <PlugZap size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">Автоматический импорт через локальный агент</h2>
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Запустите `python3 server.py` в папке `agent`, затем нажмите кнопку ниже. Сайт запросит JSON у локального
            bridge-сервера и покажет реальные findings.
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
            <h2 className="text-xl font-semibold text-white">Отчет агента</h2>
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

          <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[940px] border-collapse text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Проблема</th>
                    <th className="px-4 py-3">Риск</th>
                    <th className="px-4 py-3">Статус</th>
                    <th className="px-4 py-3">Категория</th>
                    <th className="px-4 py-3">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id} className="border-b border-slate-900 align-top last:border-b-0">
                      <td className="px-4 py-4">
                        <p className="font-semibold text-white">{finding.title}</p>
                        <p className="mt-1 max-w-xl leading-6 text-slate-400">{finding.description}</p>
                        <p className="mt-2 text-slate-300">{finding.recommendation}</p>
                      </td>
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
            </div>
          </div>
        </section>
      ) : null}
    </div>
  );
}
