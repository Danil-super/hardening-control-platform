"use client";

import { Select } from "@/components/ui/select";

import { useMemo, useState } from "react";
import { RiskBadge, StatusBadge } from "@/components/ui/badge";
import { LinkButton } from "@/components/ui/button";
import { FindingDescription } from "@/components/reports/finding-description";
import type { Finding, RiskLevel } from "@/types";

type RiskFilter = RiskLevel | "all" | "critical" | "unknown";
const riskFilters: RiskFilter[] = ["all", "critical", "high", "medium", "low", "info", "unknown"];
const riskFilterLabels: Record<RiskFilter, string> = {
  all: "Все риски",
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
  unknown: "Риск не оценён",
};

function cveAssessmentLabel(finding: Finding) {
  const assessment = finding.cveApplicability;
  if (!assessment) return null;
  if (assessment.verdict === "unknown") return "Применимость CVE не подтверждена";
  if (assessment.verdict === "under_investigation") return "Требуется проверка бюллетеня";
  if (assessment.verdict === "not_affected") return "Не затронут по данным базы Trivy";
  return "Затронут по данным базы Trivy";
}

const sourceLabels: Record<Finding["source"], string> = {
  agentless: "Ansible по SSH",
  custom: "Ansible по SSH",
  ssh_audit: "ssh-audit с control node",
  nmap: "Nmap с control node",
  lynis: "Временный запуск Lynis",
  openscap: "OpenSCAP / OVAL / XCCDF",
  trivy: "Trivy",
  greenbone: "Greenbone / OpenVAS",
  dependency_track: "OWASP Dependency-Track",
};

function categoryLabel(category: string) {
  const labels: Record<string, string> = {
    ssh: "SSH",
    accounts: "Учётные записи",
    firewall: "Firewall",
    network: "Сеть",
    updates: "Обновления",
    services: "Сервисы",
    web: "Веб-сервер",
    docker: "Docker",
    system: "Система",
  };
  return labels[category] ?? category;
}

export function FindingsExplorer({
  findings,
  reportId,
  profileId,
  hostAlias,
  remediationLinkHref,
  remediationLinkLabel = "Сформировать план исправлений",
  planLinkHref,
}: {
  findings: Finding[];
  reportId?: string;
  profileId: string;
  hostAlias?: string;
  remediationLinkHref?: string;
  remediationLinkLabel?: string;
  planLinkHref?: string;
}) {
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [category, setCategory] = useState("all");

  const categories = useMemo(
    () => ["all", ...Array.from(new Set(findings.map((finding) => finding.category)))],
    [findings],
  );

  const filteredFindings = findings.filter((finding) => {
    const level = finding.severityUnknown ? "unknown" : finding.severityAssessment?.level === "critical" ? "critical" : finding.risk;
    const riskMatch = risk === "all" || level === risk;
    const categoryMatch = category === "all" || finding.category === category;
    return riskMatch && categoryMatch;
  });

  return (
    <section className="space-y-4">
      <div className="flex flex-col gap-3 rounded-md border border-slate-800 bg-slate-950/70 p-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="text-sm font-semibold text-white">Результаты проверок</p>
          <p className="mt-1 text-sm text-slate-400">Показано: {filteredFindings.length} из {findings.length}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {riskFilters.filter((value) => (value !== "unknown" || findings.some((finding) => finding.severityUnknown))
            && (value !== "critical" || findings.some((finding) => !finding.severityUnknown && finding.severityAssessment?.level === "critical"))).map((value) => (
            <button
              key={value}
              onClick={() => setRisk(value)}
              aria-pressed={risk === value}
              className={`rounded-md border px-3 py-2 text-sm transition ${
                risk === value ? "border-sky-300 bg-sky-400 text-slate-950" : "border-slate-700 bg-slate-900 text-slate-200"
              }`}
            >
              {riskFilterLabels[value]}
            </button>
          ))}
        </div>
        <Select
          value={category}
          aria-label="Категория проверки"
          onValueChange={(value) => setCategory(value)}
          className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100"
        >
          {categories.map((value) => (
            <option key={value} value={value}>
              {value === "all" ? "Все категории" : categoryLabel(value)}
            </option>
          ))}
        </Select>
      </div>

      <div className="space-y-3">
        {filteredFindings.length ? filteredFindings.map((finding) => (
          <details key={finding.id} className="group rounded-md border border-slate-800 bg-slate-950/70 px-4 py-3">
            <summary className="flex cursor-pointer list-none flex-wrap items-start gap-3 text-sm">
              <span aria-hidden="true" className="text-sky-200 transition-transform group-open:rotate-90">›</span>
              <h3 className="min-w-0 flex-1 font-semibold text-white [overflow-wrap:anywhere]">{finding.source === "greenbone" && reportId ? <FindingDescription original={finding.title} reportId={reportId} findingId={finding.id} field="title" expanded inline lazy /> : finding.title}</h3>
              <span className="flex flex-wrap gap-2"><RiskBadge risk={finding.risk} unknown={finding.severityUnknown} critical={finding.severityAssessment?.level === "critical"} /><StatusBadge status={finding.status} /></span>
            </summary>
            <div className="mt-3 text-sm">
              <div className="leading-6 text-slate-400">{finding.source === "greenbone" && reportId ? <FindingDescription original={finding.description} reportId={reportId} findingId={finding.id} expanded lazy /> : finding.description}</div>
            {finding.cveApplicability ? (
              <div className="mt-3 rounded-md border border-sky-400/20 bg-slate-900/60 px-3 py-2 text-sm text-slate-200">
                <p className="font-medium">{cveAssessmentLabel(finding)}</p>
                <p className="mt-1 text-xs text-slate-400">Источник advisory: {finding.cveApplicability.advisory.dataSourceId ?? "не указан"} · проверка источника: {finding.cveApplicability.advisory.sourceMatch === "matched" ? "совпадает с дистрибутивом" : finding.cveApplicability.advisory.sourceMatch === "mismatch" ? "не соответствует дистрибутиву" : "не подтверждена"} · происхождение пакета: {finding.cveApplicability.package.provenance === "distribution-maintainer" ? "согласуется с метаданными ОС" : "не подтверждено"}</p>
                <p className="mt-1 text-xs text-slate-400">ID: {finding.cveApplicability.advisory.id} · пакет: {finding.cveApplicability.package.name} {finding.cveApplicability.package.installedVersion} · причина: {finding.cveApplicability.reason}. Проверка цифровой подписи производителя не выполнялась.</p>
              </div>
            ) : null}
            {finding.ubuntuOsvPreview ? (
              <div className="mt-3 rounded-md border border-amber-300/30 bg-slate-900/60 px-3 py-2 text-xs text-slate-200">
                <p className="font-medium text-amber-200">Предварительная сверка с Ubuntu OSV (не подтверждена производителем)</p>
                <p className="mt-1">Вывод по снимку: {finding.ubuntuOsvPreview.status === "unavailable" ? "данные недоступны" : finding.ubuntuOsvPreview.candidateVerdict === "affected" ? "пакет затронут" : finding.ubuntuOsvPreview.candidateVerdict === "fixed_or_not_affected" ? "исправлен по указанной версии" : finding.ubuntuOsvPreview.candidateVerdict === "needs_review" ? "нужна ручная проверка" : "нет достаточных данных"} · источник: {finding.ubuntuOsvPreview.sourcePackage} {finding.ubuntuOsvPreview.sourceVersion}</p>
                <p className="mt-1">SHA-256: <span className="break-all">{finding.ubuntuOsvPreview.snapshotSha256}</span></p>
                {finding.ubuntuOsvPreview.conflictingWithTrivy ? <p className="mt-1 font-semibold text-amber-200">Обнаружено расхождение с Trivy: сохраните оба результата и проверьте бюллетень вручную.</p> : null}
                {finding.ubuntuOsvPreview.lifecycle ? (
                  <p className="mt-1 text-slate-400">
                    Жизненный цикл OSV: {finding.ubuntuOsvPreview.lifecycle.state === "import_window_ok" ? "локальный срок импорта не превышен, актуальность у Canonical не подтверждена" : finding.ubuntuOsvPreview.lifecycle.state === "stale_import" ? "локальный снимок просрочен" : finding.ubuntuOsvPreview.lifecycle.state === "withdrawn_record" ? "бюллетень отозван" : "даты или происхождение не подтверждены"} ·
                    изменён у издателя: {finding.ubuntuOsvPreview.lifecycle.modifiedAt ?? "нет данных"} ·
                    импортирован: {finding.ubuntuOsvPreview.lifecycle.importedAt ?? "нет данных"} ·
                    предел локального хранения: {finding.ubuntuOsvPreview.lifecycle.maxImportAgeHours} ч.
                  </p>
                ) : null}
                <p className="mt-1 text-slate-400">Без подтверждения подписи издателя. Автоматическое исправление по этой сверке запрещено.</p>
              </div>
            ) : null}
            {finding.debianTrackerPreview ? (
              <div className="mt-3 rounded-md border border-amber-300/30 bg-slate-900/60 px-3 py-2 text-xs text-slate-200">
                <p className="font-medium text-amber-200">Предварительная сверка с Debian Security Tracker (издатель не аутентифицирован)</p>
                <p className="mt-1">Вывод по снимку: {finding.debianTrackerPreview.status === "unavailable" ? "нет пригодных данных" : finding.debianTrackerPreview.candidateVerdict === "affected" ? "версия ниже исправленной" : finding.debianTrackerPreview.candidateVerdict === "fixed_or_not_affected" ? "версия исправлена или не затронута по записи" : finding.debianTrackerPreview.candidateVerdict === "needs_review" ? "требуется проверка" : "недостаточно данных"} · выпуск: {finding.debianTrackerPreview.release} · исходный пакет: {finding.debianTrackerPreview.sourcePackage} {finding.debianTrackerPreview.sourceVersion}.</p>
                <p className="mt-1">Порог исправления: {finding.debianTrackerPreview.fixedVersion ?? "не указан"} · причина: {finding.debianTrackerPreview.reason}.</p>
                <p className="mt-1 break-all">SHA-256 полной базы: {finding.debianTrackerPreview.fullSnapshotSha256}.</p>
                <p className="mt-1 break-all">SHA-256 извлечённой записи: {finding.debianTrackerPreview.derivedExcerptSha256 ?? "нет пригодной записи"}.</p>
                <p className="mt-1 text-slate-400">Дата локального получения: {finding.debianTrackerPreview.capturedAt}. Актуальность и подпись издателя не подтверждены.</p>
                {finding.debianTrackerPreview.conflictingWithTrivy ? <p className="mt-1 font-semibold text-amber-200">Расхождение с Trivy — требуется ручная проверка обоих источников. Исходная находка сохранена.</p> : null}
                <p className="mt-1 text-slate-400">Сверка не разрешает автоматическое исправление и не подтверждает безопасность хоста.</p>
              </div>
            ) : null}
            <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
              <div><dt className="text-slate-500">Категория</dt><dd className="mt-1 text-slate-200">{categoryLabel(finding.category)}</dd></div>
              <div><dt className="text-slate-500">Источник</dt><dd className="mt-1 text-slate-200">{sourceLabels[finding.source]}</dd></div>
              <div><dt className="text-slate-500">Способ исправления</dt><dd className="mt-1 text-slate-200">{finding.remediationAvailable ? "Доступен в управлении хостом" : "Выполнить вручную"}</dd></div>
            </dl>
            <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/60 p-3">
              <p className="text-xs font-semibold uppercase text-slate-500">Рекомендация</p>
              <div className="mt-1 leading-6 text-slate-200">{finding.source === "greenbone" && reportId ? <FindingDescription original={finding.recommendation} reportId={reportId} findingId={finding.id} field="recommendation" expanded lazy /> : finding.recommendation}</div>
            </div>
            {finding.evidence ? (
              <details className="mt-3 rounded-md border border-slate-800 bg-slate-900/60 p-3">
                <summary className="cursor-pointer text-xs font-semibold text-slate-300">Показать технические данные</summary>
                <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">{finding.evidence}</pre>
              </details>
            ) : null}
            {finding.affectedFiles?.length ? <p className="mt-3 break-all text-xs text-slate-500">Файлы: {finding.affectedFiles.join(", ")}</p> : null}
            {finding.remediationAvailable && hostAlias ? <LinkButton href={remediationLinkHref ?? "/hosts"} variant="secondary" className="mt-4">Открыть управление хостом</LinkButton> : null}
            </div>
          </details>
        )) : (
          <div className="rounded-md border border-slate-800 bg-slate-950/70 px-4 py-8 text-center text-sm text-slate-400">Нет результатов, соответствующих выбранным фильтрам.</div>
        )}
      </div>

      {planLinkHref || findings.some((finding) => finding.remediationAvailable) ? <div className="flex justify-end">
        <LinkButton href={planLinkHref ?? remediationLinkHref ?? `/remediation?profileId=${profileId}`}>
          {planLinkHref ? "Выбрать изменения для плана" : remediationLinkLabel}
        </LinkButton>
      </div> : null}
    </section>
  );
}
