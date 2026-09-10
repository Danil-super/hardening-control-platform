import { Activity, AlertTriangle, FileText, Server, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { readIncidents } from "@/lib/ansible-control";
import { verifyAuditChain } from "@/lib/state-store";
import { listAnsibleReports, targetAliasFromReport } from "@/lib/ansible-reports";

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
  if (mode === "facts") {
    return "факты";
  }
  if (mode === "events") {
    return "события";
  }
  if (mode === "packages") {
    return "пакеты";
  }
  if (mode === "vulnerabilities") {
    return "CVE";
  }
  if (mode === "ssh-audit") {
    return "SSH crypto";
  }
  if (mode === "nmap") {
    return "Nmap";
  }
  if (mode === "lynis") {
    return "Lynis";
  }
  if (mode === "openscap") {
    return "OpenSCAP";
  }
  if (mode === "greenbone") {
    return "Greenbone";
  }
  if (mode === "dependency-track") {
    return "Dependency-Track";
  }
  return "аудит";
}

function actionLabel(action: string) {
  const labels: Record<string, string> = {
    agentlessAudit: "Аудит",
    ping: "Проверка связи",
    collectFacts: "Сбор сведений",
    packageInventory: "Проверка пакетов",
    collectEvents: "Сбор событий",
    sshCryptoAudit: "Проверка SSH",
    networkPortScan: "Проверка портов",
    lynisTemporaryAudit: "Проверка Lynis",
    openScapAudit: "Проверка OpenSCAP",
    closePort: "Закрытие порта",
    blockIp: "Блокировка IP",
  };
  return labels[action] ?? action;
}

function CommandCell({ value }: { value: string }) {
  return (
    <details className="group">
      <summary className="cursor-pointer list-none [&::-webkit-details-marker]:hidden">
        <code className="block break-all rounded-md bg-slate-900 px-2 py-1 text-xs leading-5 text-slate-300 line-clamp-2 group-open:hidden" title={value}>
          {value}
        </code>
        <span className="mt-1 block text-xs text-slate-500 group-open:hidden">Показать команду полностью</span>
      </summary>
      <code className="hidden break-all whitespace-pre-wrap rounded-md bg-slate-900 px-2 py-1 text-xs leading-5 text-slate-300 group-open:block">
        {value}
      </code>
    </details>
  );
}

export default async function AgentlessReportsPage({
  searchParams,
}: {
  searchParams: Promise<{ host?: string }>;
}) {
  const { host: requestedHost } = await searchParams;
  const hostFilter = requestedHost && /^[a-zA-Z0-9_.-]{1,64}$/.test(requestedHost) ? requestedHost : null;
  const reports = listAnsibleReports();
  const scopedReports = hostFilter
    ? reports.filter((report) => targetAliasFromReport(report) === hostFilter)
    : reports;
  const incidents = readIncidents();
  const auditIntegrity = verifyAuditChain();
  const auditReports = scopedReports.filter((report) => report.mode === "agentless");
  const latestAuditsByHost = new Map<string, (typeof auditReports)[number]>();
  for (const report of auditReports) {
    if (!report.reportTimeValid) continue;
    const alias = targetAliasFromReport(report);
    if (!latestAuditsByHost.has(alias)) {
      latestAuditsByHost.set(alias, report);
    }
  }
  const latestAudits = Array.from(latestAuditsByHost.values());
  const reportsByHost = new Map<string, typeof reports>();
  for (const report of reports) {
    const alias = targetAliasFromReport(report);
    const hostReports = reportsByHost.get(alias) ?? [];
    hostReports.push(report);
    reportsByHost.set(alias, hostReports);
  }
  const hostRows = Array.from(reportsByHost, ([host, hostReports]) => {
    const latestReport = hostReports[0];
    const mainAudit = hostReports.find((report) => report.mode === "agentless" && report.reportTimeValid) ?? null;
    return { host, hostReports, latestReport, mainAudit };
  });
  const scores = latestAudits
    .map((report) => report.score)
    .filter((score): score is number => typeof score === "number");
  const matchingProfiles = new Set(latestAudits.map((report) => report.profileId)).size === 1;
  const averageScore = scores.length && scores.length === latestAudits.length && matchingProfiles
    ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length)
    : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">История проверок</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Отчёты</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            {hostFilter
              ? `История всех запусков для хоста ${hostFilter}.`
              : "Здесь собраны сохранённые результаты аудита, проверки пакетов и события безопасности."}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {hostFilter ? <LinkButton href="/reports/agentless" variant="secondary">Все хосты</LinkButton> : null}
          {hostFilter ? <LinkButton href={`/reports/correlation/${encodeURIComponent(hostFilter)}`} variant="secondary">Единая сводка</LinkButton> : null}
          <LinkButton href="/hosts" variant="secondary">Открыть хосты</LinkButton>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Всего отчётов" value={scopedReports.length} detail={hostFilter ? "По выбранному хосту" : "Сохранённые результаты"} icon={<FileText size={18} />} />
        <SummaryCard label="Аудиты" value={auditReports.length} detail="С проблемами и оценкой" icon={<ShieldCheck size={18} />} />
        <SummaryCard label="Выполнение правил" value={averageScore === null ? "нет общей оценки" : `${averageScore}%`} detail="Полные аудиты одного профиля; не вероятность защиты" icon={<Activity size={18} />} />
        <SummaryCard label="Высокие риски" value={latestAudits.reduce((sum, report) => sum + report.high, 0)} detail="В последних аудитах" icon={<AlertTriangle size={18} />} />
      </div>

      <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        {hostFilter ? (
          <>
            <div className="border-b border-slate-800 px-4 py-3 text-sm text-slate-400">
              Все проверки и отчёты хоста <span className="font-semibold text-slate-200">{hostFilter}</span>.
            </div>
            {scopedReports.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-left text-sm">
              <thead className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Хост / отчёт</th>
                  <th className="px-4 py-3">Тип</th>
                  <th className="px-4 py-3">Оценка</th>
                  <th className="px-4 py-3">Риски</th>
                  <th className="px-4 py-3">Данные</th>
                  <th className="px-4 py-3">Дата</th>
                  <th className="px-4 py-3">Открыть</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scopedReports.map((report) => (
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
                        {report.partial ? "частичный результат" : !report.reportTimeValid ? "некорректная дата" : report.score === null ? "без общей оценки" : `${report.score}%`}
                      </span>
                      {report.mode === "lynis" ? <p className="mt-1 text-xs text-slate-500">индекс Lynis</p> : null}
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
                        <span className="text-slate-500">нет проблем</span>
                      )}
                    </td>
                    <td className="px-4 py-4 text-slate-300">
                      <p>Проблем: {report.findingsCount}</p>
                      <p className="mt-1 text-xs text-slate-500">Событий: {report.eventsCount}</p>
                    </td>
                    <td className="px-4 py-4 text-slate-300">{formatDate(report.createdAt ?? report.modifiedAt)}</td>
                    <td className="px-4 py-4">
                      <LinkButton href={`/reports/agentless/${encodeURIComponent(report.id)}`} variant="secondary">Открыть</LinkButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
            ) : (
          <div className="p-6 text-sm leading-6 text-slate-400">
            Для {hostFilter} пока нет сохраненных отчетов.
          </div>
            )}
          </>
        ) : hostRows.length ? (
          <>
            <div className="border-b border-slate-800 px-4 py-3 text-sm text-slate-400">
              Одна строка на хост. Нажмите на имя хоста или «Все тесты», чтобы открыть его полную историю.
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px] text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Хост</th>
                    <th className="px-4 py-3">Основная оценка</th>
                    <th className="px-4 py-3">Последний тест</th>
                    <th className="px-4 py-3">Тестов</th>
                    <th className="px-4 py-3">Действие</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {hostRows.map(({ host, hostReports, latestReport, mainAudit }) => (
                    <tr key={host} className="align-top">
                      <td className="px-4 py-4">
                        <Link href={`/reports/agentless?host=${encodeURIComponent(host)}`} className="inline-flex items-start gap-3 rounded-md text-left outline-none transition hover:text-sky-200 focus:ring-2 focus:ring-sky-300">
                          <Server size={18} className="mt-0.5 text-sky-200" aria-hidden="true" />
                          <span>
                            <span className="block font-semibold text-white">{host}</span>
                            <span className="mt-1 block text-xs text-slate-500">Открыть все тесты хоста</span>
                          </span>
                        </Link>
                      </td>
                      <td className="px-4 py-4">
                        {mainAudit ? (
                          <>
                            <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${scoreTone(mainAudit.score)}`}>
                              {mainAudit.score === null ? "нет score" : `${mainAudit.score}%`}
                            </span>
                            <p className="mt-1 text-xs text-slate-500">agentless-аудит</p>
                          </>
                        ) : <span className="text-slate-500">нет основного аудита</span>}
                      </td>
                      <td className="px-4 py-4 text-slate-300">
                        <p>{reportModeLabel(latestReport.mode)}</p>
                        <p className="mt-1 text-xs text-slate-500">{formatDate(latestReport.createdAt ?? latestReport.modifiedAt)}</p>
                      </td>
                      <td className="px-4 py-4 text-slate-300">{hostReports.length}</td>
                      <td className="px-4 py-4">
                        <div className="flex flex-wrap gap-2">
                          <LinkButton href={`/reports/correlation/${encodeURIComponent(host)}`} variant="secondary">Сводка</LinkButton>
                          <LinkButton href={`/reports/agentless?host=${encodeURIComponent(host)}`} variant="secondary">Все тесты ({hostReports.length})</LinkButton>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="p-6 text-sm leading-6 text-slate-400">
            Реальных отчётов пока нет. Откройте страницу хостов, настройте inventory и запустите аудит или сбор событий.
          </div>
        )}
      </section>

      <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
        <div className="flex flex-col gap-2 border-b border-slate-800 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Журнал действий</h2>
            <p className="mt-1 text-sm text-slate-400">Нельзя изменить или удалить через панель.</p>
          </div>
          <span className={`inline-flex w-fit rounded-md border px-2 py-1 text-xs font-semibold ${auditIntegrity.valid && auditIntegrity.payloadProtected ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100" : "border-amber-400/30 bg-amber-500/10 text-amber-100"}`}>
            {!auditIntegrity.valid ? "Проверка целостности не пройдена" : auditIntegrity.payloadProtected ? `Цепочка целостна · ${auditIntegrity.entries}` : `Ограниченная проверка · ${auditIntegrity.legacyEntries} старых записей`}
          </span>
        </div>
        {auditIntegrity.legacyEntries > 0 ? (
          <p className="border-b border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
            Старый формат журнала не защищал все поля события. Целостность содержимого {auditIntegrity.legacyEntries} старых записей нельзя подтвердить; история сохранена без повторного подписания. Новые записи используют полную подпись данных.
          </p>
        ) : null}
        {incidents.length ? (
          <div className="max-h-[620px] overflow-y-auto overflow-x-hidden">
            <table className="w-full table-fixed text-left text-sm">
              <colgroup>
                <col className="w-[16%]" />
                <col className="w-[16%]" />
                <col className="w-[8%]" />
                <col className="w-[12%]" />
                <col className="w-[10%]" />
                <col className="w-[38%]" />
              </colgroup>
              <thead className="sticky top-0 z-10 border-b border-slate-800 bg-slate-900 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3">Дата</th>
                  <th className="px-4 py-3">Операция</th>
                  <th className="px-4 py-3">Тип</th>
                  <th className="px-4 py-3">Хост/группа</th>
                  <th className="px-4 py-3">Статус</th>
                  <th className="px-4 py-3">Команда</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {incidents.map((incident) => (
                  <tr key={incident.id} className="align-top">
                    <td className="break-words px-4 py-4 text-slate-300">{formatDate(incident.createdAt)}</td>
                    <td className="break-words px-4 py-4 font-semibold text-white">{actionLabel(incident.action)}</td>
                    <td className="break-words px-4 py-4 text-slate-300">{incident.kind}</td>
                    <td className="break-words px-4 py-4 text-slate-300">{incident.limit ?? "Все хосты"}</td>
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
                      <CommandCell value={incident.command ?? incident.message} />
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
