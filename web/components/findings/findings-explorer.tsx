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
  agentless: "Ansible SSH",
  custom: "Ansible SSH",
};

export function FindingsExplorer({
  findings,
  profileId,
  remediationLinkHref,
  remediationLinkLabel = "Сформировать план исправлений",
}: {
  findings: Finding[];
  profileId: string;
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
          <p className="text-sm font-semibold text-white">Фильтры находок</p>
          <p className="mt-1 text-sm text-slate-400">Отберите риски перед планированием исправлений.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {riskFilters.map((value) => (
            <button
              key={value}
              onClick={() => setRisk(value)}
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
          onChange={(event) => setCategory(event.target.value)}
          className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
        >
          {categories.map((value) => (
            <option key={value} value={value}>
              {value === "all" ? "Все категории" : value}
            </option>
          ))}
        </select>
      </div>

      <div className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] border-collapse text-left text-sm">
            <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
              <tr>
                <th className="px-4 py-3">Проблема</th>
                <th className="px-4 py-3">Риск</th>
                <th className="px-4 py-3">Категория</th>
                <th className="px-4 py-3">Статус</th>
                <th className="px-4 py-3">Источник</th>
                <th className="px-4 py-3">Исправление</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.length ? filteredFindings.map((finding) => (
                <tr key={finding.id} className="border-b border-slate-900 align-top last:border-b-0">
                  <td className="px-4 py-4">
                    <p className="font-semibold text-white">{finding.title}</p>
                    <p className="mt-1 max-w-xl leading-6 text-slate-400">{finding.description}</p>
                    <p className="mt-2 text-slate-300">{finding.recommendation}</p>
                  </td>
                  <td className="px-4 py-4"><RiskBadge risk={finding.risk} /></td>
                  <td className="px-4 py-4 text-slate-300">{finding.category}</td>
                  <td className="px-4 py-4"><StatusBadge status={finding.status} /></td>
                  <td className="px-4 py-4 text-slate-300">{sourceLabels[finding.source]}</td>
                  <td className="px-4 py-4 text-slate-300">{finding.remediationAvailable ? "доступно" : "вручную"}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-400">
                    Для выбранных фильтров находок нет.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex justify-end">
        <LinkButton href={remediationLinkHref ?? `/remediation?profileId=${profileId}`}>
          {remediationLinkLabel}
        </LinkButton>
      </div>
    </section>
  );
}
