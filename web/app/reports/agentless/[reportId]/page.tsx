import { notFound } from "next/navigation";
import { AlertTriangle, Download, FileText, ListChecks, Server, ShieldCheck } from "lucide-react";
import { FindingsExplorer } from "@/components/findings/findings-explorer";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { readAnsibleReport, targetAliasFromReport } from "@/lib/ansible-reports";

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

function fileModifiedDate(value: unknown) {
  if (typeof value === "number") {
    const date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? "нет данных" : date.toLocaleString("ru-RU");
  }
  return formatDate(typeof value === "string" ? value : null);
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
  const targetAlias = targetAliasFromReport(report);
  const raw = asRecord(report.raw);
  const packageInventory = asRecord(raw.packageInventory);
  const vulnerabilityScan = asRecord(raw.vulnerabilityScan);
  const trivyFreshness = asRecord(vulnerabilityScan.databaseFreshness);
  const scanner = asRecord(raw.scanner);
  const vendorAssessment = asRecord(vulnerabilityScan.vendorAssessment);
  const vendorStatuses = Object.entries(asRecord(vendorAssessment.statuses))
    .filter(([, value]) => typeof value === "number" && Number.isFinite(value))
    .map(([status, count]) => `${status}: ${count}`);
  const isLynisReport = report.mode === "lynis";
  const isOpenScapReport = report.mode === "openscap";
  const freshnessLabels: Record<string, string> = { fresh: "актуальна", stale: "устарела", missing: "отсутствует", unknown: "актуальность неизвестна" };
  const exceptionsApplied = Array.isArray(scanner.exceptionsApplied) ? scanner.exceptionsApplied : [];

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

      {report.partial || !report.reportTimeValid ? (
        <section role="status" className="rounded-md border border-amber-400/30 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
          <p className="font-semibold">{report.available ? "Проверка неполная" : "Сканер не выполнил проверку"}</p>
          <p>{!report.reportTimeValid ? "Дата отчёта некорректна: его нельзя использовать как актуальное свидетельство." : "Отсутствие находок в этом отчёте не подтверждает защищённость хоста. Устраните причину и повторите проверку."}</p>
          {typeof vulnerabilityScan.message === "string" ? <p className="mt-1">{vulnerabilityScan.message}</p> : null}
        </section>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard
          label={isLynisReport ? "Индекс Lynis" : "Оценка"}
          value={report.score === null ? "не рассчитана" : isLynisReport ? `${report.score}/100` : `${report.score}%`}
          detail={isLynisReport ? "Индекс харденинга Lynis" : isOpenScapReport ? "По правилам выбранного профиля" : report.mode === "vulnerabilities" ? "CVE не переводятся в процент защищённости" : "В пределах выполненных проверок"}
          icon={<ShieldCheck size={18} />}
        />
        <SummaryCard label="Высокий" value={report.high} detail="Срочный приоритет" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Средний" value={report.medium} detail="Плановое действие" icon={<FileText size={18} />} />
        <SummaryCard label="Проверки" value={report.findingsCount} detail="Записи в отчёте" icon={<Server size={18} />} />
        <SummaryCard label="События" value={report.eventsCount} detail="События безопасности" icon={<ListChecks size={18} />} />
      </div>

      {report.needsReview && !report.partial ? <p className="text-sm leading-6 text-amber-100">Часть результатов требует ручной оценки. Завершение сбора данных не означает, что все настройки признаны безопасными.</p> : null}

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
          {Object.keys(trivyFreshness).length ? <p className={`mt-4 rounded-md border px-3 py-2 text-sm leading-6 ${trivyFreshness.status === "fresh" ? "border-emerald-400/25 bg-emerald-500/5 text-emerald-100" : "border-amber-400/25 bg-amber-500/5 text-amber-100"}`}>База Trivy: {freshnessLabels[String(trivyFreshness.status)] ?? "актуальность неизвестна"} · дата: {formatDate(typeof trivyFreshness.updatedAt === "string" ? trivyFreshness.updatedAt : null)} · возраст: {textValue(trivyFreshness.ageHours)} ч · лимит: {textValue(trivyFreshness.maxAgeHours)} ч.</p> : null}
        </section>
      ) : null}

      {isOpenScapReport ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Параметры OpenSCAP</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Профиль и datastream фиксируются в отчёте, чтобы результат можно было воспроизвести и сопоставить после обновления SSG.</p>
          <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div><p className="text-slate-500">Группа политики</p><p className="mt-1 break-words text-slate-200">{textValue(scanner.policyGroup)}</p></div>
            <div><p className="text-slate-500">SSG-профиль</p><p className="mt-1 break-all text-slate-200">{textValue(scanner.profile)}</p></div>
            <div><p className="text-slate-500">Datastream</p><p className="mt-1 break-all text-slate-200">{textValue(scanner.datastream)}</p></div>
            <div><p className="text-slate-500">Контрольная сумма datastream</p><p className="mt-1 break-all text-slate-200">{textValue(scanner.datastreamChecksum)}</p><p className="mt-1 text-xs text-slate-500">Изменён: {fileModifiedDate(scanner.datastreamLastModified)}</p></div>
          </div>
          {exceptionsApplied.length ? <p className="mt-4 rounded-md border border-amber-400/25 bg-amber-500/5 px-3 py-2 text-sm leading-6 text-amber-100">Согласованных исключений: {exceptionsApplied.length}. Причина и срок указаны в находках. Исходный результат проверки и уровень риска сохранены.</p> : null}
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
          В отчёте нет записей о находках и событиях. Объём и полноту проверки уточняйте по статусу отчёта и исходному JSON.
        </section>
      ) : null}
    </div>
  );
}
