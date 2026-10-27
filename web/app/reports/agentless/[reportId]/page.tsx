import { notFound } from "next/navigation";
import { AlertTriangle, Download, FileText, ListChecks, Server, ShieldCheck } from "lucide-react";
import { FindingsExplorer } from "@/components/findings/findings-explorer";
import { SecurityEventsView } from "@/components/reports/security-events-view";
import { OvalFindingsView } from "@/components/reports/oval-findings-view";
import { LynisFindingsView } from "@/components/reports/lynis-findings-view";
import { LinkButton } from "@/components/ui/button";
import { SummaryCard } from "@/components/ui/summary-card";
import { describeIncompleteAuditChecks } from "@/lib/audit-coverage";
import { readAnsibleReport, targetAliasFromReport } from "@/lib/ansible-reports";
import { describeAstraOvalNextStep } from "@/lib/astra-oval-policy";
import { auditReportLimitations } from "@/lib/audit-result";

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
  if (mode === "agentless") return "Основной аудит профиля";
  if (mode === "facts") return "Сведения о хосте";
  if (mode === "packages") return "Инвентаризация пакетов";
  if (mode === "vulnerabilities") return "CVE-аудит пакетов";
  if (mode === "events") return "Отчет по событиям безопасности";
  if (mode === "ssh-audit") return "Проверка криптографии SSH";
  if (mode === "nmap") return "Проверка открытых портов";
  if (mode === "lynis") return "Lynis: временный аудит без установки";
  if (mode === "openscap") return "OpenSCAP: проверка выбранного профиля";
  if (mode === "astra-oval") return "Astra: CVE по выбранной OVAL-базе";
  if (mode === "greenbone") return "Greenbone / OpenVAS: импорт сетевого отчёта";
  if (mode === "dependency-track") return "OWASP Dependency-Track: передача SBOM";
  return "Аудит Ansible";
}

function profileTitle(profileId: string | null) {
  const titles: Record<string, string> = {
    basic_linux: "Базовый Linux",
    ssh_security: "SSH-сервер",
    web_server: "Веб-сервер",
    docker_host: "Docker-хост",
    facts: "Сбор сведений",
    events: "Сбор событий",
    packages: "Инвентаризация пакетов",
  };
  return profileId ? titles[profileId] ?? profileId : "без профиля";
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
  const defaultIpv4 = asRecord(raw.defaultIpv4);
  const packageInventory = asRecord(raw.packageInventory);
  const vulnerabilityScan = asRecord(raw.vulnerabilityScan);
  const isAstraTrivyReport = report.mode === "vulnerabilities" && report.available && vulnerabilityScan.provider === "Trivy" && /astra/i.test(report.os ?? "");
  const sourcePackages = isAstraTrivyReport && typeof vulnerabilityScan.sourcePackageReportId === "string" ? readAnsibleReport(vulnerabilityScan.sourcePackageReportId) : null;
  const astraVersion = asRecord(asRecord(sourcePackages?.raw).packageInventory).astraVersion;
  const astraNextStep = isAstraTrivyReport ? describeAstraOvalNextStep(targetAlias, typeof astraVersion === "string" ? astraVersion : null) : null;
  const trivyFreshness = asRecord(vulnerabilityScan.databaseFreshness);
  const scanner = asRecord(raw.scanner);
  const incompleteChecks = describeIncompleteAuditChecks(scanner.incompleteChecks);
  const scannerPartialReasons = auditReportLimitations(report.raw);
  const ovalDatabase = asRecord(scanner.database);
  const ovalIdentity = asRecord(scanner.hostIdentity);
  const ovalValidation = asRecord(scanner.sourceValidation);
  const ovalDefinitions = Array.isArray(scanner.definitionResults) ? scanner.definitionResults.map(asRecord) : [];
  const vendorAssessment = asRecord(vulnerabilityScan.vendorAssessment);
  const vendorStatuses = Object.entries(asRecord(vendorAssessment.statuses))
    .filter(([, value]) => typeof value === "number" && Number.isFinite(value))
    .map(([status, count]) => `${status}: ${count}`);
  const isLynisReport = report.mode === "lynis";
  const isOvalReport = report.mode === "astra-oval";
  const ovalFindings = report.findings.filter((finding) => finding.status === "failed");
  const ovalCritical = ovalFindings.filter((finding) => finding.severityAssessment?.level === "critical").length;
  const ovalUnknown = ovalFindings.filter((finding) => finding.severityUnknown).length;
  const isOpenScapReport = report.mode === "openscap";
  const isNmapReport = report.mode === "nmap";
  const freshnessLabels: Record<string, string> = { fresh: "актуальна", stale: "устарела", missing: "отсутствует", unknown: "актуальность неизвестна" };
  const exceptionsApplied = Array.isArray(scanner.exceptionsApplied) ? scanner.exceptionsApplied : [];
  const nmapScopeLabels: Record<string, string> = {
    top_100: "Быстрая: 100 наиболее распространённых TCP-портов",
    top_1000: "Стандартная: 1 000 наиболее распространённых TCP-портов",
    full_tcp: "Полная TCP-проверка: порты 1–65 535",
  };
  const nmapScope = nmapScopeLabels[String(scanner.scanScope)] ?? textValue(scanner.scope);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <h1 className="break-words text-3xl font-semibold text-white">{report.host}</h1>
          <p className="mt-2 max-w-3xl text-slate-400">
            {reportModeTitle(report.mode)} ·{" "}
            {formatDate(report.createdAt ?? report.modifiedAt)}
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <LinkButton href={`/reports/agentless?host=${encodeURIComponent(targetAlias)}`} variant="secondary">История хоста</LinkButton>
          <LinkButton href={`/reports/correlation/${encodeURIComponent(targetAlias)}`} variant="secondary">Единая сводка</LinkButton>
          {["facts", "events", "packages"].includes(report.mode) ? <LinkButton href="/hosts">Перейти к проверкам</LinkButton> : <LinkButton href={`/remediation-plan?host=${encodeURIComponent(targetAlias)}`}>Выбрать изменения</LinkButton>}
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
            <p className="mt-2 text-sm text-slate-300">{profileTitle(report.profileId)}</p>
            {report.profileId ? <p className="mt-1 text-xs text-slate-500">{report.profileId}</p> : null}
          </div>
          <div>
            <p className="text-xs font-semibold uppercase text-slate-500">Источник</p>
            <p className="mt-2 text-sm text-slate-300">{vulnerabilityScan.provider === "Trivy" ? "Trivy на управляющей машине" : "Control node Ansible"}</p>
          </div>
        </div>
      </section>

      {report.partial || !report.reportTimeValid ? (
        <section role="status" className="rounded-xl border border-amber-400/30 bg-amber-500/10 p-5 text-sm leading-6 text-amber-100">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <p className="font-semibold">{!report.available ? "Сканер не выполнил проверку" : isAstraTrivyReport ? "Для CVE Astra нужен OVAL-аудит" : "Проверка неполная"}</p>
              <p className="mt-1">{!report.reportTimeValid ? "Дата отчёта некорректна: его нельзя использовать как актуальное свидетельство." : isAstraTrivyReport ? "Пакеты собраны, но Trivy не поддерживает базу CVE производителя Astra. Даже свежая база Trivy не позволяет подтвердить отсутствие уязвимостей этой ОС." : "Часть контролей не дала достоверный ответ. Поэтому отсутствие находок и общая оценка не означают, что хост защищён."}</p>
            </div>
            {report.mode === "agentless" ? <LinkButton href="/hosts" variant="secondary">Повторить после исправления</LinkButton> : null}
          </div>
          {incompleteChecks.length ? (
            <div className="mt-4 rounded-lg border border-amber-300/20 bg-slate-950/30 p-4 text-slate-100">
              <h2 className="font-semibold">Что не удалось проверить</h2>
              <ol className="mt-3 space-y-3">
                {incompleteChecks.map((check, index) => (
                  <li key={check.id} className="grid gap-1 sm:grid-cols-[1.75rem_minmax(0,1fr)]">
                    <span className="flex h-7 w-7 items-center justify-center rounded-full border border-amber-300/30 bg-amber-400/10 text-xs font-semibold text-amber-100">{index + 1}</span>
                    <div>
                      <p className="font-semibold text-white">{check.title}</p>
                      <p className="text-slate-300">{check.description}</p>
                      <p className="mt-1 text-sky-100">Следующий шаг: {check.nextStep}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          ) : scannerPartialReasons.length ? <div className="mt-3 text-slate-200"><p className="font-semibold">Причины ограничения</p><ul className="mt-2 list-inside list-disc space-y-1">{scannerPartialReasons.slice(0, 20).map((reason, index) => <li key={index} className="break-words">{reason}</li>)}</ul>{scannerPartialReasons.length > 20 ? <p className="mt-2">Остальные причины доступны в JSON.</p> : null}</div> : report.partial && !isAstraTrivyReport && !vulnerabilityScan.message ? <p className="mt-3 text-slate-200">Точная причина не записана этим источником. Откройте JSON или технические данные отчёта, устраните ошибку сбора и повторите проверку.</p> : null}
          {astraNextStep ? <div className="mt-3"><p className="text-slate-200">{astraNextStep.message}</p><LinkButton href={astraNextStep.href} variant="secondary" className="mt-3">{astraNextStep.ready ? "Перейти к проверке CVE Astra" : "Исправить OVAL-источник"}</LinkButton></div> : typeof vulnerabilityScan.message === "string" ? <p className="mt-3 text-slate-200">{vulnerabilityScan.message}</p> : null}
        </section>
      ) : null}

      {isNmapReport ? (
        <section className="rounded-md border border-sky-400/25 bg-sky-500/5 p-4 text-sm leading-6 text-sky-100">
          <h2 className="font-semibold">Охват проверки Nmap</h2>
          <p className="mt-1">{nmapScope}.</p>
          <p className="mt-1 text-slate-300">{scanner.coverageComplete === true
            ? "Все TCP-порты проверены. UDP, локальные сокеты и сценарии уязвимостей в этот запуск не входят."
            : "Это ограниченная выборка TCP-портов: отсутствие находок вне указанного диапазона не подтверждено. Для полного TCP-охвата запустите «Полная TCP: 1–65 535». UDP выполняется отдельной согласованной проверкой."}</p>
        </section>
      ) : null}

      {report.mode === "facts" || report.mode === "events" ? (
        <section className="rounded-md border border-sky-400/25 bg-sky-500/5 p-5 text-sm leading-6 text-sky-100">
          <h2 className="font-semibold">{report.partial || !report.available ? "Полученные данные" : report.mode === "facts" ? "Сведения о хосте собраны" : `Сбор событий завершён · записей: ${report.eventsCount}`}</h2>
          <p className="mt-1 text-slate-300">{report.mode === "facts" ? "Ansible получил параметры системы, оборудования и сети. Они приведены ниже. Этот тест собирает сведения и не рассчитывает оценку безопасности." : "Ниже — сообщения журналов с пояснениями. Количество событий не является количеством уязвимостей; оценка безопасности в этом тесте не рассчитывается."}</p>
        </section>
      ) : isOvalReport ? <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <SummaryCard label="Уникальных CVE" value={textValue(scanner.uniqueCveCount)} detail={`${ovalFindings.length} срабатываний OVAL`} icon={<ListChecks size={18} />} />
        <SummaryCard label="Критические" value={ovalCritical} detail="Срабатывания с явной оценкой" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Высокие" value={report.high - ovalCritical} detail="Без критических" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Средние" value={report.medium} detail="Срабатывания с явной оценкой" icon={<FileText size={18} />} />
        <SummaryCard label="Риск не оценён" value={ovalUnknown} detail="Критичность неизвестна" icon={<ShieldCheck size={18} />} />
      </div> : isLynisReport ? <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Индекс Lynis" value={report.score === null ? "не рассчитан" : `${report.score}/100`} detail="Индекс усиления, не процент безопасности" icon={<ShieldCheck size={18} />} />
        <SummaryCard label="Предупреждения" value={report.lynisWarnings ?? 0} detail="Требуют проверки применимости" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Советы по усилению" value={report.lynisSuggestions ?? 0} detail="Оцените необходимость для роли хоста" icon={<FileText size={18} />} />
        <SummaryCard label="Сбор данных" value={report.partial ? "Незавершён" : "Завершён"} detail={`Lynis ${textValue(scanner.version)} · ${report.findingsCount} записей`} icon={<ListChecks size={18} />} />
      </div> : <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard label="Высокий" value={report.high} detail="Срочный приоритет" icon={<AlertTriangle size={18} />} />
        <SummaryCard label="Средний" value={report.medium} detail="Плановое действие" icon={<FileText size={18} />} />
        <SummaryCard label="Проверки" value={report.findingsCount} detail="Записи в отчёте" icon={<Server size={18} />} />
        <SummaryCard label="События" value={report.eventsCount} detail="События безопасности" icon={<ListChecks size={18} />} />
      </div>}

      {isOvalReport && ovalUnknown > 0 ? <p className="rounded-lg border border-amber-400/25 bg-amber-500/5 p-4 text-sm leading-6 text-amber-100">У {ovalUnknown} срабатываний критичность неизвестна. Оценки Chromium взяты из явно указанного поля в описаниях базы; CVSS не вычислялся. Нули в отдельных категориях не подтверждают отсутствие опасных уязвимостей.</p> : report.needsReview && !report.partial && !isOvalReport ? <p className="text-sm leading-6 text-amber-100">Часть результатов требует ручной оценки. Завершение сбора данных не означает, что все настройки признаны безопасными.</p> : null}

      {report.mode === "facts" ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Собранные сведения</h2>
          <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div><p className="text-slate-500">Ядро</p><p className="mt-1 text-slate-200">{textValue(raw.kernel)}</p></div>
            <div><p className="text-slate-500">Архитектура</p><p className="mt-1 text-slate-200">{textValue(raw.architecture)}</p></div>
            <div><p className="text-slate-500">Память</p><p className="mt-1 text-slate-200">{textValue(raw.memoryMb)} MB</p></div>
            <div><p className="text-slate-500">vCPU</p><p className="mt-1 text-slate-200">{textValue(raw.processorCount)}</p></div>
            <div><p className="text-slate-500">Виртуализация</p><p className="mt-1 text-slate-200">{textValue(raw.virtualizationType)}</p></div>
            <div><p className="text-slate-500">Тип системы</p><p className="mt-1 text-slate-200">{raw.virtualizationRole === "guest" ? "Виртуальная машина" : raw.virtualizationRole === "host" ? "Хост виртуализации" : textValue(raw.virtualizationRole)}</p></div>
            <div><p className="text-slate-500">Интерфейсы</p><p className="mt-1 break-words text-slate-200">{Array.isArray(raw.interfaces) ? raw.interfaces.join(", ") : "нет данных"}</p></div>
          </div>
          <h3 className="mt-6 font-semibold text-white">Основное сетевое подключение</h3>
          <dl className="mt-3 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
            {[ ["IPv4-адрес", defaultIpv4.address], ["Маска сети", defaultIpv4.netmask], ["Шлюз", defaultIpv4.gateway], ["Интерфейс", defaultIpv4.interface], ["MAC-адрес", defaultIpv4.macaddress], ["Сеть", defaultIpv4.network], ["MTU", defaultIpv4.mtu] ].map(([label, value]) => <div key={String(label)}><dt className="text-slate-400">{String(label)}</dt><dd className="mt-1 break-words text-slate-200">{textValue(value)}</dd></div>)}
          </dl>
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

      {report.mode === "astra-oval" ? <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
        <h2 className="text-xl font-semibold text-white">Результат OVAL-аудита Astra</h2>
        <p className="mt-2 text-sm leading-6 text-slate-300">Проверено {textValue(scanner.evaluatedDefinitionCount)} из {textValue(scanner.definitionCount)} определений. Выпуск хоста: {textValue(ovalIdentity.astraVersion)}. База: {formatDate(typeof ovalDatabase.generatedAt === "string" ? ovalDatabase.generatedAt : null)}.</p>
        <p className="mt-2 text-sm leading-6 text-slate-400">Результат относится к выбранной базе OVAL. Список ниже содержит сработавшие определения; подробности раскрываются по нажатию на строку.</p>
        <details className="mt-4"><summary className="cursor-pointer text-sm font-semibold text-sky-200">Источник базы и технические сведения</summary>
        <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
          <div><p className="text-slate-500">Определений в базе / результатов</p><p className="mt-1 text-slate-200">{textValue(scanner.definitionCount)} / {textValue(scanner.evaluatedDefinitionCount)}</p></div>
          <div><p className="text-slate-500">Выпуск хоста / область базы</p><p className="mt-1 break-words text-slate-200">{textValue(ovalIdentity.astraVersion)} / {textValue(ovalDatabase.releasePattern)}</p></div>
          <div><p className="text-slate-500">Сканер</p><p className="mt-1 break-words text-slate-200">{textValue(scanner.version)}</p></div>
          {ovalValidation.location === "control_node" ? <div className="sm:col-span-2"><p className="text-slate-500">Проверка XML базы</p><p className="mt-1 text-slate-200">Управляющий узел · XSD: успешно · Schematron: {ovalValidation.schematronExitCode === 0 ? "успешно" : "превышено время проверки"}</p><p className="mt-1 text-xs text-slate-500">{textValue(ovalValidation.validator)}</p></div> : null}
          <div><p className="text-slate-500">База сформирована</p><p className="mt-1 text-slate-200">{formatDate(typeof ovalDatabase.generatedAt === "string" ? ovalDatabase.generatedAt : null)}</p></div>
          <div><p className="text-slate-500">Свежесть / возраст</p><p className="mt-1 text-slate-200">{{ current: "в пределах срока", stale: "устарела", future: "дата в будущем" }[String(ovalDatabase.freshness)] ?? "не подтверждена"} / {textValue(ovalDatabase.ageDays)} дн.</p></div>
          <div className="min-w-0 sm:col-span-2"><p className="text-slate-500">Файл базы / URL</p><p className="mt-1 break-all text-slate-200">{textValue(ovalDatabase.url ?? ovalDatabase.path)}</p></div>
          <div><p className="text-slate-500">Доверенный источник</p><p className="mt-1 break-words text-slate-200">{textValue(ovalDatabase.sourceName)}</p></div>
          <div className="min-w-0 sm:col-span-2"><p className="text-slate-500">Реквизит источника</p><p className="mt-1 break-all text-slate-200">{textValue(ovalDatabase.sourceReference)}</p></div>
          <div><p className="text-slate-500">Реквизиты сверены</p><p className="mt-1 text-slate-200">{formatDate(typeof ovalDatabase.sourceReviewedAt === "string" ? ovalDatabase.sourceReviewedAt : null)}</p></div>
        </div>
        <p className="mt-4 break-all text-xs leading-5 text-slate-400">SHA-256: {textValue(ovalDatabase.sha256)} · {ovalDatabase.checksumVerified === true ? "совпадает с заданным" : "доверенная сумма не подтверждена"}</p>
        <p className="mt-3 text-sm leading-6 text-slate-400">CVE учитывается при истинном определении класса vulnerability. Результаты других классов сохраняются отдельно. Если база не содержит оценку критичности, CVSS и уровень риска не придумываются.</p>
        <p className="mt-2 text-sm leading-6 text-slate-400">В JSON {report.findingsCount} записей, включая сведения об области оценки. Полнота всех известных CVE и подпись производителя автоматически не подтверждаются.</p>
        {ovalDefinitions.length ? <details className="mt-4"><summary className="cursor-pointer text-sm font-semibold text-sky-200">Результаты определений ({ovalDefinitions.length})</summary>
          <div className="mt-3 overflow-x-auto"><table className="w-full min-w-[620px] text-left text-xs"><thead><tr className="border-b border-slate-700 text-slate-400"><th className="p-2">Определение</th><th className="p-2">Класс</th><th className="p-2">Результат</th><th className="p-2">Связанные CVE</th></tr></thead>
            <tbody>{ovalDefinitions.slice(0, 100).map((definition, index) => <tr key={index} className="border-b border-slate-800 text-slate-300"><td className="max-w-sm break-words p-2">{textValue(definition.id)}<br />{textValue(definition.title)}</td><td className="p-2">{textValue(definition.class)}</td><td className="p-2">{textValue(definition.result)}</td><td className="max-w-xs break-words p-2">{Array.isArray(definition.cveIds) ? definition.cveIds.join(", ") || "—" : "—"}</td></tr>)}</tbody>
          </table></div><p className="mt-2 text-xs text-slate-500">Показаны первые {Math.min(100, ovalDefinitions.length)} определений. Полные результаты, условия и сведения о пакетах доступны в JSON. Ссылка на CVE сама по себе не означает её обнаружение.</p>
        </details> : null}
        </details>
      </section> : null}

      {isOpenScapReport ? (
        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Параметры OpenSCAP</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Профиль и контрольная сумма содержимого фиксируются для воспроизведения проверки. Профиль HCP для Astra охватывает базовые настройки и не является сертификационным.</p>
          <div className="mt-4 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div><p className="text-slate-500">Группа политики</p><p className="mt-1 break-words text-slate-200">{textValue(scanner.policyGroup)}</p></div>
            <div><p className="text-slate-500">Профиль</p><p className="mt-1 break-all text-slate-200">{textValue(scanner.profile)}</p></div>
            <div><p className="text-slate-500">Datastream</p><p className="mt-1 break-all text-slate-200">{textValue(scanner.datastream)}</p></div>
            <div><p className="text-slate-500">Контрольная сумма datastream</p><p className="mt-1 break-all text-slate-200">{textValue(scanner.datastreamChecksum)}</p><p className="mt-1 text-xs text-slate-500">Изменён: {fileModifiedDate(scanner.datastreamLastModified)}</p></div>
          </div>
          <LinkButton href="/policies" variant="secondary" className="mt-3">Настроить профиль OpenSCAP</LinkButton>
          {exceptionsApplied.length ? <p className="mt-4 rounded-md border border-amber-400/25 bg-amber-500/5 px-3 py-2 text-sm leading-6 text-amber-100">Согласованных исключений: {exceptionsApplied.length}. Причина и срок указаны в находках. Исходный результат проверки и уровень риска сохранены.</p> : null}
        </section>
      ) : null}

      {isLynisReport ? <LynisFindingsView findings={report.findings} reportId={report.id} /> : isOvalReport ? <OvalFindingsView findings={report.findings} reportId={report.id} /> : report.findings.length ? (
        <FindingsExplorer
          reportId={report.id}
          findings={astraNextStep ? report.findings.map((finding) => finding.id === "trivy_incomplete_coverage" ? { ...finding, recommendation: astraNextStep.message } : finding) : report.findings}
          profileId={report.profileId ?? "basic_linux"}
          hostAlias={targetAlias}
          remediationLinkHref="/hosts"
          remediationLinkLabel="Открыть управление хостами"
          planLinkHref={`/remediation-plan?host=${encodeURIComponent(targetAlias)}`}
        />
      ) : null}

      {report.events.length ? <SecurityEventsView events={report.events} /> : null}

      {report.mode === "events" && !report.events.length ? <p className="rounded-md border border-slate-800 p-5 text-sm text-slate-300">В доступной выборке журналов подходящих событий нет. Этот результат относится только к прочитанным журналам.</p> : null}

      {!report.findings.length && !report.events.length && !["facts", "events", "packages"].includes(report.mode) ? (
        <section className="rounded-md border border-amber-400/30 bg-amber-500/10 p-5 text-sm leading-6 text-amber-100">
          В отчёте нет записей о находках и событиях. Объём и полноту проверки уточняйте по статусу отчёта и исходному JSON.
        </section>
      ) : null}
    </div>
  );
}
