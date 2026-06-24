import { notFound } from "next/navigation";
import { AlertTriangle, Download, FileText, ListChecks, Server, ShieldCheck } from "lucide-react";
import { FindingsExplorer } from "@/components/findings/findings-explorer";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { readAnsibleReport } from "@/lib/ansible-reports";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function formatDate(value: string | null | undefined) {
  if (!value) {
    return "нет данных";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function targetAliasFromReport(fileName: string, profileId: string | null, mode: string) {
  if (mode === "events") {
    return fileName.replace(/-events\.json$/i, "");
  }
  if (mode === "packages") {
    return fileName.replace(/-packages\.json$/i, "");
  }
  if (mode === "vulnerabilities") {
    return fileName.replace(/-vulnerabilities\.json$/i, "");
  }
  if (profileId && fileName.endsWith(`-${profileId}.json`)) {
    return fileName.slice(0, -`-${profileId}.json`.length);
  }
  return fileName.replace(/\.json$/i, "");
}

export default async function AgentlessReportDetailPage({
  params,
}: {
  params: Promise<{ reportId: string }>;
}) {
  const { reportId } = await params;
  const report = readAnsibleReport(decodeURIComponent(reportId));

  if (!report) {
    notFound();
  }
  const targetAlias = targetAliasFromReport(report.fileName, report.profileId, report.mode);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">{report.host}</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            {report.mode === "events" ? "Отчет по событиям безопасности" : "SSH-аудит Ansible"} ·{" "}
            {formatDate(report.createdAt ?? report.modifiedAt)}
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <LinkButton href="/reports/agentless" variant="secondary">Все отчеты</LinkButton>
          <LinkButton href={`/api/ansible/reports/${encodeURIComponent(report.id)}`} variant="secondary">
            <Download size={16} aria-hidden="true" />
            JSON
          </LinkButton>
        </div>
      </div>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Файл</p>
            <p className="mt-2 break-all text-sm text-slate-300">{report.fileName}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Hostname / OS</p>
            <p className="mt-2 text-sm text-slate-300">{report.hostname ?? report.host}</p>
            <p className="mt-1 text-xs text-slate-500">{report.os ?? "ОС не указана"}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Профиль</p>
            <p className="mt-2 text-sm text-slate-300">{report.profileId ?? "без профиля"}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Источник</p>
            <p className="mt-2 text-sm text-slate-300">Ansible control node</p>
          </div>
        </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard label="Оценка" value={report.score === null ? "нет" : `${report.score}%`} detail="По активным рискам" icon={<ShieldCheck size={18} />} />
        <SummaryCard label="Высокий" value={report.high} detail="Срочный приоритет" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Средний" value={report.medium} detail="Плановое действие" icon={<FileText size={18} />} />
        <SummaryCard label="Findings" value={report.findingsCount} detail="Проверки аудита" icon={<Server size={18} />} />
        <SummaryCard label="Events" value={report.eventsCount} detail="События безопасности" icon={<ListChecks size={18} />} />
      </div>

      {report.findings.length ? (
        <FindingsExplorer
          findings={report.findings}
          profileId={report.profileId ?? "basic_linux"}
          hostAlias={targetAlias}
          remediationLinkHref="/hosts"
          remediationLinkLabel="Открыть управление хостами"
        />
      ) : null}

      {report.events.length ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <div className="flex items-center gap-3">
            <ListChecks size={22} className="text-sky-200" aria-hidden="true" />
            <h2 className="text-xl font-semibold text-white">События безопасности</h2>
          </div>
          <div className="mt-4 max-h-[520px] overflow-auto rounded-md border border-slate-800 bg-slate-900/70">
            {report.events.map((event, index) => (
              <div key={`${event.source ?? "event"}-${index}`} className="border-b border-slate-800 p-4 text-sm last:border-b-0">
                <p className="font-semibold text-slate-200">{event.source ?? "source"}</p>
                <p className="mt-2 break-words leading-6 text-slate-400">{event.message ?? "Пустое событие"}</p>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {!report.findings.length && !report.events.length ? (
        <section className="rounded-md border border-amber-400/30 bg-amber-500/10 p-5 text-sm leading-6 text-amber-100">
          В этом JSON нет массива `findings` или `events`. Откройте исходный JSON для ручной проверки структуры.
        </section>
      ) : null}
    </div>
  );
}
