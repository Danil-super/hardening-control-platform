import { Activity, AlertTriangle, FileText, ListChecks, Server, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { readIncidents } from "@/lib/ansible-control";
import { listAnsibleReports } from "@/lib/ansible-reports";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function formatDate(value: string | null | undefined) {
  if (!value) {
    return "нет данных";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function scoreTone(score: number | null) {
  if (typeof score !== "number") {
    return "border-slate-700 bg-slate-900 text-slate-300";
  }
  if (score >= 80) {
    return "border-emerald-400/40 bg-emerald-500/15 text-emerald-100";
  }
  if (score >= 55) {
    return "border-amber-400/40 bg-amber-500/15 text-amber-100";
  }
  return "border-red-400/40 bg-red-500/15 text-red-100";
}

function reportModeLabel(mode: string) {
  if (mode === "events") {
    return "события";
  }
  if (mode === "packages") {
    return "пакеты";
  }
  if (mode === "vulnerabilities") {
    return "CVE";
  }
  return "аудит";
}

export default function AgentlessReportsPage() {
  const reports = listAnsibleReports();
  const incidents = readIncidents().slice(0, 20);
  const auditReports = reports.filter((report) => report.findingsCount > 0);
  const eventReports = reports.filter((report) => report.mode === "events" || report.eventsCount > 0);
  const scores = auditReports
    .map((report) => report.score)
    .filter((score): score is number => typeof score === "number");
  const averageScore = scores.length
    ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length)
    : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">Реальные Ansible-отчеты</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            История JSON-отчетов из `ansible/reports`: SSH-аудиты Ansible, события безопасности, оценки и риски по хостам.
          </p>
        </div>
        <LinkButton href="/hosts" variant="secondary">Открыть хосты</LinkButton>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard label="Всего отчетов" value={reports.length} detail="Файлы JSON" icon={<FileText size={18} />} />
        <SummaryCard label="Аудиты" value={auditReports.length} detail="С findings и score" icon={<ShieldCheck size={18} />} />
        <SummaryCard label="События" value={eventReports.length} detail="Auth/UFW/Suricata" icon={<ListChecks size={18} />} />
        <SummaryCard label="Средняя оценка" value={averageScore === null ? "нет" : `${averageScore}%`} detail="По audit-отчетам" icon={<Activity size={18} />} />
        <SummaryCard label="Высокие риски" value={auditReports.reduce((sum, report) => sum + report.high, 0)} detail="Суммарно по отчетам" icon={<AlertTriangle size={18} />} />
      </div>

      <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        {reports.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-left text-sm">
              <thead className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Хост</th>
                  <th className="px-4 py-3">Тип</th>
                  <th className="px-4 py-3">Оценка</th>
                  <th className="px-4 py-3">Риски</th>
                  <th className="px-4 py-3">Записей</th>
                  <th className="px-4 py-3">Дата</th>
                  <th className="px-4 py-3">Действие</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {reports.map((report) => (
                  <tr key={report.id} className="align-top">
                    <td className="px-4 py-4">
                      <div className="flex items-start gap-3">
                        <Server size={18} className="mt-0.5 text-sky-200" aria-hidden="true" />
                        <div>
                          <p className="font-semibold text-white">{report.host}</p>
                          <p className="mt-1 text-xs text-slate-500">{report.fileName}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4 text-slate-300">
                      <p>{reportModeLabel(report.mode)}</p>
                      <p className="mt-1 text-xs text-slate-500">{report.profileId ?? "без профиля"}</p>
                    </td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${scoreTone(report.score)}`}>
                        {report.score === null ? "нет score" : `${report.score}%`}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-xs text-slate-300">
                      {report.findingsCount ? (
                        <div className="grid grid-cols-4 gap-1">
                          <span className="rounded-md bg-red-500/15 px-2 py-1 text-red-100">H {report.high}</span>
                          <span className="rounded-md bg-amber-500/15 px-2 py-1 text-amber-100">M {report.medium}</span>
                          <span className="rounded-md bg-sky-500/15 px-2 py-1 text-sky-100">L {report.low}</span>
                          <span className="rounded-md bg-slate-800 px-2 py-1 text-slate-300">I {report.info}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500">нет findings</span>
                      )}
                    </td>
                    <td className="px-4 py-4 text-slate-300">
                      <p>findings: {report.findingsCount}</p>
                      <p className="mt-1 text-xs text-slate-500">events: {report.eventsCount}</p>
                    </td>
                    <td className="px-4 py-4 text-slate-300">{formatDate(report.createdAt ?? report.modifiedAt)}</td>
                    <td className="px-4 py-4">
                      <LinkButton href={`/reports/agentless/${encodeURIComponent(report.id)}`} variant="secondary">
                        Открыть
                      </LinkButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-sm leading-6 text-slate-400">
            Реальных отчетов пока нет. Откройте страницу хостов, настройте inventory и запустите “SSH-аудит Ansible”
            или “Собрать события”. После этого JSON появится здесь автоматически.
          </div>
        )}
      </section>

      <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        <div className="border-b border-slate-800 p-4">
          <h2 className="text-lg font-semibold text-white">История запусков</h2>
          <p className="mt-1 text-sm text-slate-400">Последние audit и response действия на главном сервере.</p>
        </div>
        {incidents.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-left text-sm">
              <thead className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Дата</th>
                  <th className="px-4 py-3">Действие</th>
                  <th className="px-4 py-3">Тип</th>
                  <th className="px-4 py-3">Хост/группа</th>
                  <th className="px-4 py-3">Статус</th>
                  <th className="px-4 py-3">Команда</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {incidents.map((incident) => (
                  <tr key={incident.id} className="align-top">
                    <td className="px-4 py-4 text-slate-300">{formatDate(incident.createdAt)}</td>
                    <td className="px-4 py-4 font-semibold text-white">{incident.action}</td>
                    <td className="px-4 py-4 text-slate-300">{incident.kind}</td>
                    <td className="px-4 py-4 text-slate-300">{incident.limit ?? "all"}</td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${
                        incident.status === "success"
                          ? "border-emerald-400/40 bg-emerald-500/15 text-emerald-100"
                          : "border-red-400/40 bg-red-500/15 text-red-100"
                      }`}>
                        {incident.status === "success" ? "успешно" : "ошибка"}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <code className="block max-w-xl truncate rounded-md bg-slate-900 px-2 py-1 text-xs text-slate-300" title={incident.command ?? incident.message}>
                        {incident.command ?? incident.message}
                      </code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-5 text-sm text-slate-400">Запусков пока нет.</div>
        )}
      </section>
    </div>
  );
}
