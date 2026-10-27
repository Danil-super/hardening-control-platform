import { notFound } from "next/navigation";
import { AlertTriangle, CheckCircle2, FileText, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import { RiskBadge } from "@/components/ui/badge";
import { SummaryCard } from "@/components/ui/summary-card";
import { buildHostCorrelation } from "@/lib/audit-correlation";
import { riskBandOf } from "@/lib/host-risk-summary";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const sourceLabels: Record<string, string> = {
  agentless: "Ansible",
  custom: "Ansible",
  ssh_audit: "ssh-audit",
  nmap: "Nmap",
  lynis: "Lynis",
  openscap: "OpenSCAP",
  trivy: "Trivy",
  greenbone: "Greenbone",
  dependency_track: "Dependency-Track",
};

function formatDate(value: string | null) {
  if (!value) return "нет даты";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

export default async function HostCorrelationPage({ params, searchParams }: { params: Promise<{ hostAlias: string }>; searchParams: Promise<{ risk?: string | string[]; page?: string | string[]; q?: string | string[] }> }) {
  const { hostAlias } = await params;
  const report = buildHostCorrelation(decodeURIComponent(hostAlias));
  if (!report) notFound();
  const query = await searchParams;
  const labels: Record<string, string> = { all: "Все", critical: "Критические", high: "Высокие", medium: "Средние", low: "Низкие", unknown: "Не оценены", info: "Информация" };
  const selectedRisk = typeof query.risk === "string" && Object.hasOwn(labels, query.risk) ? query.risk : "all";
  const search = (typeof query.q === "string" ? query.q : "").slice(0, 200);
  const filtered = report.findings.filter((finding) => (selectedRisk === "all" || riskBandOf(finding) === selectedRisk)
    && (!search || `${finding.title} ${finding.description}`.toLocaleLowerCase("ru").includes(search.toLocaleLowerCase("ru"))));
  const pageCount = Math.max(1, Math.ceil(filtered.length / 25));
  const page = Math.max(1, Math.min(pageCount, typeof query.page === "string" && Number.isFinite(Number(query.page)) ? Math.floor(Number(query.page)) : 1));
  const pageHref = (number: number, risk = selectedRisk) => `?${new URLSearchParams({ risk, page: String(number), ...(search ? { q: search } : {}) })}`;
  const manual = report.findings.filter((item) => item.confidence === "manual").length;
  const high = report.findings.filter((item) => riskBandOf(item) === "high").length;
  const critical = report.findings.filter((item) => riskBandOf(item) === "critical").length;
  const unknown = report.findings.filter((item) => item.severityUnknown).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Единая оценка доказательств</p>
          <h1 className="mt-2 break-words text-3xl font-semibold text-white">{report.hostAlias}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Последний отчёт каждого инструмента и профиля, не старше {report.maxAgeHours} ч. Повторные запуски из истории не суммируются. Совпадающие технические признаки объединяются; разные CVE, компоненты и условия сохраняются отдельно.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <LinkButton href={`/remediation-plan?host=${encodeURIComponent(report.hostAlias)}`}>План устранения</LinkButton>
          <LinkButton href={`/reports/agentless?host=${encodeURIComponent(report.hostAlias)}`} variant="secondary">Все исходные отчёты</LinkButton>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <SummaryCard label="Наблюдения" value={report.findings.length} detail={`Требуют ручной проверки: ${manual}`} icon={<FileText size={18} />} />
        <SummaryCard label="Критические" value={critical} detail="С явной оценкой из источника" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Высокие" value={high} detail="Без критических находок" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Не оценены" value={unknown} detail="Критичность неизвестна" icon={<CheckCircle2 size={18} />} />
        <SummaryCard label="Полные свежие проверки" value={report.freshReports.filter((item) => !item.partial).length} detail={`Неполных или устаревших: ${report.partialReports.length}`} icon={<ShieldCheck size={18} />} />
      </div>

      {report.staleReports.length ? (
        <section className="rounded-md border border-amber-400/30 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
          В сводку не включены источники с устаревшей или некорректной датой: {report.staleReports.map((item) => `${item.mode} (${formatDate(item.createdAt)})`).join(", ")}. Повторите соответствующий аудит, прежде чем принимать решение.
        </section>
      ) : null}

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
        <h2 className="font-semibold text-white">Покрытие проверками</h2>
        <p className="mt-2 text-sm text-slate-400">Совпадение CVE или порта не подтверждает уязвимость. Передача SBOM и сбор сведений не являются завершённым аудитом.</p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {report.coverage.map((item) => (
            <p key={item.reportId} className="text-sm text-slate-300">
              {item.mode}: {!item.auditEvidence ? "сведения / передача данных" : !item.available ? "недоступен" : !item.validTime ? "некорректная дата" : !item.fresh ? "устарел" : item.partial ? "частичный результат" : "завершён"}
            </p>
          ))}
          {!report.coverage.length ? <p className="text-sm text-slate-400">Проверки ещё не проводились.</p> : null}
        </div>
      </section>

      <section className="space-y-3">
        <div className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="font-semibold text-white">Наблюдения по хосту</h2>
          <div className="flex flex-wrap gap-2">{Object.entries(labels).map(([risk, label]) => <LinkButton key={risk} href={pageHref(1, risk)} prefetch={false} variant={risk === selectedRisk ? "primary" : "secondary"}>{label} · {risk === "all" ? report.findings.length : report.findings.filter((finding) => riskBandOf(finding) === risk).length}</LinkButton>)}</div>
          <form className="flex flex-wrap gap-2" method="get"><input type="hidden" name="risk" value={selectedRisk} /><input type="search" name="q" aria-label="Поиск наблюдений" defaultValue={search} placeholder="CVE, пакет или проверка" className="min-h-11 min-w-0 flex-1 rounded-xl border border-slate-700 px-3 py-2 text-sm" /><button className="rounded-xl border border-slate-700 px-4 py-2 text-sm text-slate-200">Найти</button></form>
          <p className="text-sm text-slate-400">Показано {filtered.length ? (page - 1) * 25 + 1 : 0}–{Math.min(page * 25, filtered.length)} из {filtered.length}</p>
        </div>
        {filtered.length ? filtered.slice((page - 1) * 25, page * 25).map((finding) => (
          <article key={finding.id} className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{finding.category}</p>
                <h2 className="mt-1 text-lg font-semibold text-white">{finding.title}</h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">{finding.description}</p>
              </div>
              <div className="flex flex-wrap gap-2 text-xs font-semibold">
                {riskBandOf(finding) === "critical" ? <span className="rounded-md border border-red-400/40 bg-red-500/15 px-2 py-1 uppercase text-red-100">Критический</span> : <RiskBadge risk={finding.risk} unknown={finding.severityUnknown} />}
                <span className="rounded-md border border-sky-400/30 bg-sky-500/10 px-2 py-1 text-sky-100">
                  {finding.confidence === "manual" ? "ручная оценка" : "обнаруженные признаки"}
                </span>
              </div>
            </div>
            <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/60 p-3">
              <p className="text-xs font-semibold uppercase text-slate-500">Рекомендация</p>
              <p className="mt-1 text-sm leading-6 text-slate-200">{finding.recommendation}</p>
            </div>
            <div className="mt-4 grid gap-2 lg:grid-cols-2">
              {finding.sources.map((source) => (
                <details key={`${source.reportId}-${source.findingId}`} className="rounded-md border border-slate-800 bg-slate-900/60 p-3">
                  <summary className="cursor-pointer text-sm text-slate-200">
                    {sourceLabels[source.source] ?? source.source} · {source.title}
                  </summary>
                  <p className="mt-2 text-xs text-slate-500">{formatDate(source.createdAt)} · {source.status}</p>
                  <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">{source.evidence}</pre>
                  <LinkButton href={`/reports/agentless/${encodeURIComponent(source.reportId)}`} variant="secondary" className="mt-3">Исходный отчёт</LinkButton>
                </details>
              ))}
            </div>
          </article>
        )) : (
          <div className="rounded-md border border-slate-800 bg-slate-950/70 p-6 text-sm leading-6 text-slate-400">
            {report.findings.length ? "Нет наблюдений по выбранным условиям." : "Свежих наблюдений нет. Это не означает, что хост безопасен: проверьте покрытие источниками и даты последних запусков."}
          </div>
        )}
        <nav aria-label="Страницы наблюдений" className="flex items-center justify-between gap-3">{page > 1 ? <LinkButton href={pageHref(page - 1)} prefetch={false} variant="secondary">Назад</LinkButton> : <span />}<span className="text-sm text-slate-400">{page} / {pageCount}</span>{page < pageCount ? <LinkButton href={pageHref(page + 1)} prefetch={false} variant="secondary">Далее</LinkButton> : <span />}</nav>
      </section>
    </div>
  );
}
