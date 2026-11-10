"use client";

import { ArrowRight } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { HostSourceGuidance } from "@/components/hosts/host-source-guidance";
import { selectHostAuditNextStep } from "@/lib/host-audit-workflow";
import type { DashboardHostEvidence } from "@/lib/dashboard-evidence-status";

type Host = { alias: string; riskSummary?: DashboardHostEvidence["riskSummary"] };

export function HostAuditNextStep({
  hosts, host, onSelectHost, controlReady, activeJob, recoveryRequired,
}: {
  hosts: Host[];
  host: Host | null;
  onSelectHost: (alias: string) => void;
  controlReady: boolean;
  activeJob: boolean;
  recoveryRequired: boolean;
}) {
  const next = selectHostAuditNextStep({
    alias: host?.alias ?? null,
    riskSummary: host?.riskSummary,
    controlReady, activeJob, recoveryRequired,
  });
  const tone = next.tone === "critical" ? "border-red-400/35 bg-red-500/10"
    : next.tone === "attention" ? "border-amber-400/25 bg-amber-500/5"
      : "border-sky-400/20 bg-sky-400/5";
  return (
    <div id="host-audit-flow" className="mt-3 space-y-3">
      {hosts.length > 0 ? <label className="block max-w-sm text-xs text-slate-400">Выбранный хост
        <Select value={host?.alias ?? ""} onValueChange={onSelectHost} aria-label="Выберите хост для маршрута проверки" className="mt-2 w-full">
          {hosts.map(item => <option key={item.alias} value={item.alias}>{item.alias}</option>)}
        </Select>
      </label> : null}
      <div className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3 py-2 ${tone}`}>
        <span className="text-sm text-slate-200">{next.title}</span>
        {next.href ? <LinkButton href={next.href} variant={next.tone === "critical" ? "danger" : "secondary"} className="[&]:min-h-8 [&]:px-3 [&]:py-1 [&]:text-xs">{next.action}<ArrowRight size={14} aria-hidden="true" /></LinkButton> : null}
      </div>
      {next.tone === "critical" ? <p role="status" className="text-xs text-amber-100">{next.detail}</p> : null}
      <details className="text-xs text-slate-400"><summary className="cursor-pointer text-sky-200">Готовность и источники</summary>
        {next.tone !== "critical" ? <p className="mt-2">{next.detail}</p> : null}
        <HostSourceGuidance alias={host?.alias ?? null} />
      </details>
    </div>
  );
}
