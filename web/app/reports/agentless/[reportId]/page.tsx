import { notFound } from "next/navigation";
import { AlertTriangle, Download, FileText, ListChecks, Server, ShieldCheck } from "lucide-react";
import { FindingsExplorer } from "@/components/findings/findings-explorer";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { readAnsibleReport, targetAliasFromReportFileName } from "@/lib/ansible-reports";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function formatDate(value: string | null | undefined) {
  if (!value) {
    return "нет данных";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function reportModeTitle(mode: string) {
  if (mode === "facts") return "Сведения о хосте";
  if (mode === "packages") return "Инвентаризация пакетов";
  if (mode === "vulnerabilities") return "CVE-аудит пакетов";
  if (mode === "events") return "Отчет по событиям безопасности";
  if (mode === "ssh-audit") return "Проверка криптографии SSH";
  if (mode === "nmap") return "Проверка открытых портов";
  if (mode === "lynis") return "Lynis: временный аудит без установки";
  if (mode === "openscap") return "OpenSCAP: соответствие заданному SSG-профилю";
  if (mode === "greenbone") return "Greenbone / OpenVAS: импорт сетевого отчёта";
  if (mode === "dependency-track") return "OWASP Dependency-Track: передача SBOM";
  return "SSH-аудит Ansible";
}

function asRecord(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function textValue(value: unknown) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "нет данных";
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
  const targetAlias = targetAliasFromReportFileName(report.fileName, report.profileId, report.mode);
  const raw = asRecord(report.raw);
  const packageInventory = asRecord(raw.packageInventory);
  const vulnerabilityScan = asRecord(raw.vulnerabilityScan);
  const vendorAssessment = asRecord(vulnerabilityScan.vendorAssessment);
  const vendorStatuses = Object.entries(asRecord(vendorAssessment.statuses))
    .filter(([, value]) => typeof value === "number" && Number.isFinite(value))
    .map(([status, count]) => `${status}: ${count}`);
  const isLynisReport = report.mode === "lynis";

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-white">{report.host}</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            {reportModeTitle(report.mode)} ·{" "}
            {formatDate(report.createdAt ?? report.modifiedAt)}
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <LinkButton href={`/reports/agentless?host=${encodeURIComponent(targetAlias)}`} variant="secondary">История хоста</LinkButton>
          <LinkButton href={`/reports/correlation/${encodeURIComponent(targetAlias)}`} variant="secondary">Единая сводка</LinkButton>
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
            <p className="text-xs font-semibold uppercase text-slate-500">Хост и ОС</p>
            <p className="mt-2 text-sm text-slate-300">{report.hostname ?? report.host}</p>
            <p className="mt-1 text-xs text-slate-500">{report.os ?? "ОС не указана"}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Профиль</p>
            <p className="mt-2 text-sm text-slate-300">{report.profileId ?? "без профиля"}</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Источник</p>
            <p className="mt-2 text-sm text-slate-300">Control node Ansible</p>
          </div>
        </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard
          label={isLynisReport ? "Индекс Lynis" : "Оценка"}
          value={report.score === null ? "нет" : `${report.score}%`}
          detail={isLynisReport ? "Hardening index Lynis, не процент соответствия" : "По активным рискам"}
          icon={<ShieldCheck size={18} />}
        />
        <SummaryCard label="Высокий" value={report.high} detail="Срочный приоритет" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Средний" value={report.medium} detail="Плановое действие" icon={<FileText size={18} />} />
        <SummaryCard label="Проблемы" value={report.findingsCount} detail="Находки аудита" icon={<Server size={18} />} />
        <SummaryCard label="События" value={report.eventsCount} detail="События безопасности" icon={<ListChecks size={18} />} />
      </div>

      {report.mode === "facts" ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Собранные сведения</h2>
          <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div><p className="text-slate-500">Ядро</p><p className="mt-1 text-slate-200">{textValue(raw.kernel)}</p></div>
            <div><p className="text-slate-500">Архитектура</p><p className="mt-1 text-slate-200">{textValue(raw.architecture)}</p></div>
            <div><p className="text-slate-500">Память</p><p className="mt-1 text-slate-200">{textValue(raw.memoryMb)} MB</p></div>
            <div><p className="text-slate-500">vCPU</p><p className="mt-1 text-slate-200">{textValue(raw.processorCount)}</p></div>
            <div><p className="text-slate-500">Виртуализация</p><p className="mt-1 text-slate-200">{textValue(raw.virtualizationType)}</p></div>
            <div><p className="text-slate-500">Интерфейсы</p><p className="mt-1 break-words text-slate-200">{Array.isArray(raw.interfaces) ? raw.interfaces.join(", ") : "нет данных"}</p></div>
          </div>
        </section>
      ) : null}

      {report.mode === "packages" ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Инвентарь пакетов</h2>
          <div className="mt-4 grid gap-4 text-sm sm:grid-cols-3">
            <div><p className="text-slate-500">Пакетов найдено</p><p className="mt-1 text-2xl font-semibold text-white">{textValue(packageInventory.packageCount)}</p></div>
            <div><p className="text-slate-500">Менеджер</p><p className="mt-1 text-slate-200">{textValue(packageInventory.manager)}</p></div>
            <div><p className="text-slate-500">CVE</p><p className="mt-1 text-slate-200">Запустите проверку пакетов и CVE через Trivy.</p></div>
          </div>
        </section>
      ) : null}

      {report.mode === "vulnerabilities" ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Статус поставщика пакетов</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{textValue(vendorAssessment.note)}</p>
          <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div><p className="text-slate-500">Провайдер</p><p className="mt-1 text-slate-200">{textValue(vulnerabilityScan.provider)}</p></div>
            <div><p className="text-slate-500">Метод оценки</p><p className="mt-1 text-slate-200">{textValue(vendorAssessment.method)}</p></div>
            <div><p className="text-slate-500">Статус в базе</p><p className="mt-1 text-slate-200">{vendorAssessment.verified === true ? "получен" : "не получен — требуется advisory поставщика"}</p></div>
            <div><p className="text-slate-500">Состояния</p><p className="mt-1 break-words text-slate-200">{vendorStatuses.length ? vendorStatuses.join(", ") : "нет CVE или статусов"}</p></div>
          </div>
        </section>
      ) : null}

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
          В отчёте нет проблем и событий, требующих отдельного просмотра. Исходный JSON можно скачать при необходимости.
        </section>
      ) : null}
    </div>
  );
}
