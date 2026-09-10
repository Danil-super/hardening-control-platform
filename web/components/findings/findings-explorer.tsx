"use client";

import { useMemo, useState } from "react";
import { RiskBadge, StatusBadge } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/button";
import type { Finding, RiskLevel } from "@/types";

const riskFilters: Array<RiskLevel | "all"> = ["all", "high", "medium", "low", "info"];
const riskFilterLabels: Record<RiskLevel | "all", string> = {
  all: "Все риски",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
};

const sourceLabels: Record<Finding["source"], string> = {
  agentless: "Ansible по SSH",
  custom: "Ansible по SSH",
  ssh_audit: "ssh-audit с control node",
  nmap: "Nmap с control node",
  lynis: "Временный запуск Lynis",
  openscap: "OpenSCAP / SCAP Security Guide",
  trivy: "Trivy",
  greenbone: "Greenbone / OpenVAS",
  dependency_track: "OWASP Dependency-Track",
};

function categoryLabel(category: string) {
  const labels: Record<string, string> = {
    ssh: "SSH",
    accounts: "Учётные записи",
    firewall: "Firewall",
    network: "Сеть",
    updates: "Обновления",
    services: "Сервисы",
    web: "Веб-сервер",
    docker: "Docker",
    system: "Система",
  };
  return labels[category] ?? category;
}

export function FindingsExplorer({
  findings,
  profileId,
  hostAlias,
  remediationLinkHref,
  remediationLinkLabel = "Сформировать план исправлений",
}: {
  findings: Finding[];
  profileId: string;
  hostAlias?: string;
  remediationLinkHref?: string;
  remediationLinkLabel?: string;
}) {
  const [risk, setRisk] = useState<RiskLevel | "all">("all");
  const [category, setCategory] = useState("all");

  const categories = useMemo(
    () => ["all", ...Array.from(new Set(findings.map((finding) => finding.category)))],
    [findings],
  );

  const filteredFindings = findings.filter((finding) => {
    const riskMatch = risk === "all" || finding.risk === risk;
    const categoryMatch = category === "all" || finding.category === category;
    return riskMatch && categoryMatch;
  });

  return (
    <section className="space-y-4">
      <div className="flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950/70 p-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-sm font-semibold text-white">Результаты проверок</p>
          <p className="mt-1 text-sm text-slate-400">Показано: {filteredFindings.length} из {findings.length}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {riskFilters.map((value) => (
            <button
              key={value}
              onClick={() => setRisk(value)}
              aria-pressed={risk === value}
              className={`rounded-md border px-3 py-2 text-sm transition ${
                risk === value ? "border-sky-300 bg-sky-400 text-slate-950" : "border-slate-700 bg-slate-900 text-slate-200"
              }`}
            >
              {riskFilterLabels[value]}
            </button>
          ))}
        </div>
        <select
          value={category}
          aria-label="Категория проверки"
          onChange={(event) => setCategory(event.target.value)}
          className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
        >
          {categories.map((value) => (
            <option key={value} value={value}>
              {value === "all" ? "Все категории" : categoryLabel(value)}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-3">
        {filteredFindings.length ? filteredFindings.map((finding) => (
          <article key={finding.id} className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h3 className="font-semibold text-white">{finding.title}</h3>
                <p className="mt-1 leading-6 text-slate-400">{finding.description}</p>
              </div>
              <div className="flex shrink-0 flex-wrap gap-2"><RiskBadge risk={finding.risk} /><StatusBadge status={finding.status} /></div>
            </div>
            <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
              <div><dt className="text-slate-500">Категория</dt><dd className="mt-1 text-slate-200">{categoryLabel(finding.category)}</dd></div>
              <div><dt className="text-slate-500">Источник</dt><dd className="mt-1 text-slate-200">{sourceLabels[finding.source]}</dd></div>
              <div><dt className="text-slate-500">Способ исправления</dt><dd className="mt-1 text-slate-200">{finding.remediationAvailable ? "Доступен в управлении хостом" : "Выполнить вручную"}</dd></div>
            </dl>
            <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/60 p-3">
              <p className="text-xs font-semibold uppercase text-slate-500">Рекомендация</p>
              <p className="mt-1 leading-6 text-slate-200">{finding.recommendation}</p>
            </div>
            {finding.evidence ? (
              <details className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3">
                <summary className="cursor-pointer text-xs font-semibold text-slate-300">Показать технические данные</summary>
                <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">{finding.evidence}</pre>
              </details>
            ) : null}
            {finding.affectedFiles?.length ? <p className="mt-3 break-all text-xs text-slate-500">Файлы: {finding.affectedFiles.join(", ")}</p> : null}
            {finding.remediationAvailable && hostAlias ? <LinkButton href={remediationLinkHref ?? "/hosts"} variant="secondary" className="mt-4">Открыть управление хостом</LinkButton> : null}
          </article>
        )) : (
          <div className="rounded-md border border-slate-800 bg-slate-950/70 px-4 py-8 text-center text-sm text-slate-400">Нет результатов, соответствующих выбранным фильтрам.</div>
        )}
      </div>

      {findings.some((finding) => finding.remediationAvailable) ? <div className="flex justify-end">
        <LinkButton href={remediationLinkHref ?? `/remediation?profileId=${profileId}`}>
          {remediationLinkLabel}
        </LinkButton>
      </div> : null}
    </section>
  );
}
