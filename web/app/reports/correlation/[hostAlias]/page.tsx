import { notFound } from "next/navigation";
import { AlertTriangle, CheckCircle2, FileText, ShieldCheck } from "lucide-react";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { buildHostCorrelation } from "@/lib/audit-correlation";

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

function riskTone(risk: string) {
  if (risk === "high") return "border-red-400/40 bg-red-500/15 text-red-100";
  if (risk === "medium") return "border-amber-400/40 bg-amber-500/15 text-amber-100";
  if (risk === "low") return "border-sky-400/40 bg-sky-500/15 text-sky-100";
  return "border-slate-700 bg-slate-900 text-slate-300";
}

export default async function HostCorrelationPage({ params }: { params: Promise<{ hostAlias: string }> }) {
  const { hostAlias } = await params;
  const report = buildHostCorrelation(decodeURIComponent(hostAlias));
  if (!report) notFound();
  const manual = report.findings.filter((item) => item.confidence === "manual").length;
  const high = report.findings.filter((item) => item.risk === "high").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Единая оценка доказательств</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">{report.hostAlias}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Только последние отчёты не старше {report.maxAgeHours} ч. Сводка объединяет совпадающие технические признаки, но не складывает CVSS и не заменяет подтверждение владельцем системы.
          </p>
        </div>
        <LinkButton href={`/reports/agentless?host=${encodeURIComponent(report.hostAlias)}`} variant="secondary">Все исходные отчёты</LinkButton>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Проблемы" value={report.findings.length} detail="Только свежие доказательства" icon={<FileText size={18} />} />
        <SummaryCard label="Требуют проверки" value={manual} detail="Неполные результаты или исключения" icon={<CheckCircle2 size={18} />} />
        <SummaryCard label="Высокий риск" value={high} detail="Не является суммой CVSS" icon={<AlertTriangle size={18} />} />
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
        {report.findings.length ? report.findings.map((finding) => (
          <article key={finding.id} className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{finding.category}</p>
                <h2 className="mt-1 text-lg font-semibold text-white">{finding.title}</h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">{finding.description}</p>
              </div>
              <div className="flex flex-wrap gap-2 text-xs font-semibold">
                <span className={`rounded-md border px-2 py-1 ${riskTone(finding.risk)}`}>{finding.risk}</span>
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
            Свежих проблем для корреляции нет. Это не означает, что хост безопасен: проверьте покрытие источниками и дату их последних запусков.
          </div>
        )}
      </section>
    </div>
  );
}
