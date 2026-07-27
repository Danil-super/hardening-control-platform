"use client";

import { useMemo, useState } from "react";
import { RiskBadge, StatusBadge } from "@/components/ui/badge";
import { Button, LinkButton } from "@/components/ui/button";
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
  ssh_audit: "ssh-audit · control node",
  nmap: "Nmap · control node",
  lynis: "Lynis · временный запуск",
};

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
  const [runningFindingId, setRunningFindingId] = useState("");
  const [message, setMessage] = useState("");
  const [pendingFinding, setPendingFinding] = useState<Finding | null>(null);

  const categories = useMemo(
    () => ["all", ...Array.from(new Set(findings.map((finding) => finding.category)))],
    [findings],
  );

  const filteredFindings = findings.filter((finding) => {
    const riskMatch = risk === "all" || finding.risk === risk;
    const categoryMatch = category === "all" || finding.category === category;
    return riskMatch && categoryMatch;
  });

  function evidenceValue(finding: Finding, key: string) {
    const parts = finding.evidence?.split(";").map((part) => part.trim()) ?? [];
    const prefix = `${key}=`;
    return parts.find((part) => part.startsWith(prefix))?.slice(prefix.length).trim() ?? "";
  }

  function remediationRequest(finding: Finding) {
    if (finding.remediationId === "close_dangerous_ports") {
      return { action: "closeDangerousPorts", extraVars: {} };
    }
    if (finding.remediationId === "update_package") {
      const packageName = evidenceValue(finding, "package");
      return packageName ? { action: "updatePackage", extraVars: { package_name: packageName } } : null;
    }
    return null;
  }

  function remediationLabel(action: string) {
    if (action === "closeDangerousPorts") {
      return "Закрыть распространенные опасные порты через активный firewall.";
    }
    if (action === "updatePackage") {
      return "Обновить выбранный пакет через пакетный менеджер дистрибутива.";
    }
    return "Запустить разрешенный response-playbook.";
  }

  async function runRemediation(finding: Finding) {
    const request = remediationRequest(finding);
    if (!request || !hostAlias) {
      setMessage("Для этой находки нет автоматического действия.");
      return;
    }

    setRunningFindingId(finding.id);
    setMessage("");
    try {
      const response = await fetch("/api/ansible/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: request.action,
          profileId,
          limit: hostAlias,
          confirmResponse: true,
          extraVars: request.extraVars,
        }),
      });
      const payload = await response.json();
      setMessage(payload.ok ? "Исправление выполнено. Запустите аудит повторно." : payload.message ?? "Исправление завершилось ошибкой.");
      if (payload.ok) {
        setPendingFinding(null);
      }
    } finally {
      setRunningFindingId("");
    }
  }

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
          <table className="w-full min-w-[820px] table-fixed border-collapse text-left text-sm">
            <colgroup>
              <col className="w-[46%]" />
              <col className="w-[9%]" />
              <col className="w-[13%]" />
              <col className="w-[11%]" />
              <col className="w-[10%]" />
              <col className="w-[11%]" />
            </colgroup>
            <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
              <tr>
                <th className="px-3 py-3">Проблема</th>
                <th className="px-3 py-3">Риск</th>
                <th className="px-3 py-3">Категория</th>
                <th className="px-3 py-3">Статус</th>
                <th className="px-3 py-3">Источник</th>
                <th className="px-3 py-3">Исправление</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.length ? filteredFindings.map((finding) => (
                <tr key={finding.id} className="border-b border-slate-900 align-top last:border-b-0">
                  <td className="px-3 py-3">
                    <p className="font-semibold text-white">{finding.title}</p>
                    <p className="mt-1 max-w-xl leading-6 text-slate-400">{finding.description}</p>
                    <p className="mt-2 text-slate-300">{finding.recommendation}</p>
                    {finding.evidence ? (
                      <pre className="mt-3 max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-md border border-slate-800 bg-slate-900/80 p-3 text-xs leading-5 text-slate-300">
                        {finding.evidence}
                      </pre>
                    ) : null}
                    {finding.affectedFiles?.length ? (
                      <p className="mt-2 break-all text-xs text-slate-500">
                        Файлы: {finding.affectedFiles.join(", ")}
                      </p>
                    ) : null}
                  </td>
                  <td className="px-3 py-3"><RiskBadge risk={finding.risk} /></td>
                  <td className="break-words px-3 py-3 text-slate-300">{finding.category}</td>
                  <td className="px-3 py-3"><StatusBadge status={finding.status} /></td>
                  <td className="break-words px-3 py-3 text-slate-300">{sourceLabels[finding.source]}</td>
                  <td className="break-words px-3 py-3 text-slate-300">
                    {remediationRequest(finding) && hostAlias ? (
                      <Button
                        variant="secondary"
                        onClick={() => setPendingFinding(finding)}
                        disabled={Boolean(runningFindingId)}
                      >
                        Исправить
                      </Button>
                    ) : finding.remediationAvailable ? "доступно" : "вручную"}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-slate-400">
                    Для выбранных фильтров находок нет.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {message ? (
        <div className="flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-300 md:flex-row md:items-center md:justify-between">
          <span>{message}</span>
          {message.startsWith("Исправление выполнено") ? (
            <LinkButton href="/hosts" variant="secondary">
              Перепроверить
            </LinkButton>
          ) : null}
        </div>
      ) : null}

      {pendingFinding ? (() => {
        const request = remediationRequest(pendingFinding);
        return request ? (
          <div className="rounded-md border border-amber-400/30 bg-amber-500/10 p-4">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <p className="text-sm font-semibold text-amber-100">Подтверждение исправления</p>
                <h3 className="mt-2 text-lg font-semibold text-white">{pendingFinding.title}</h3>
                <p className="mt-2 text-sm leading-6 text-amber-100">{remediationLabel(request.action)}</p>
                <div className="mt-3 grid gap-2 text-xs text-slate-300 md:grid-cols-3">
                  <code className="rounded-md bg-slate-950/70 p-2">playbook: {request.action}</code>
                  <code className="rounded-md bg-slate-950/70 p-2">limit: {hostAlias}</code>
                  <code className="rounded-md bg-slate-950/70 p-2">
                    vars: {Object.keys(request.extraVars).length ? JSON.stringify(request.extraVars) : "нет"}
                  </code>
                </div>
              </div>
              <div className="flex shrink-0 gap-2">
                <Button variant="secondary" onClick={() => setPendingFinding(null)} disabled={Boolean(runningFindingId)}>
                  Отмена
                </Button>
                <Button variant="danger" onClick={() => runRemediation(pendingFinding)} disabled={Boolean(runningFindingId)}>
                  {runningFindingId === pendingFinding.id ? "Запуск..." : "Запустить"}
                </Button>
              </div>
            </div>
          </div>
        ) : null;
      })() : null}

      <div className="flex justify-end">
        <LinkButton href={remediationLinkHref ?? `/remediation?profileId=${profileId}`}>
          {remediationLinkLabel}
        </LinkButton>
      </div>
    </section>
  );
}
