import { describeHostAuditEvidence, type DashboardHostEvidence } from "@/lib/dashboard-evidence-status";

/**
 * Read-only navigation derived from persisted, source-bound audit evidence.
 * This deliberately does not start jobs, assert full CVE coverage, or authorize remediation.
 */
export type HostAuditWorkflowInput = {
  alias: string | null;
  riskSummary?: DashboardHostEvidence["riskSummary"];
  controlReady: boolean;
  activeJob?: boolean;
  recoveryRequired?: boolean;
};

export type HostAuditNextStep = {
  id: "connect" | "recovery" | "controller" | "running" | "identity" | "first_audit"
    | "repeat" | "coverage" | "triage" | "report";
  title: string;
  detail: string;
  action: string;
  href: string | null;
  tone: "neutral" | "attention" | "critical";
};

const count = (value: unknown): number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;

export function selectHostAuditNextStep(input: HostAuditWorkflowInput): HostAuditNextStep {
  const alias = input.alias;
  if (!alias) return {
    id: "connect", title: "Подключите первый хост",
    detail: "Добавьте разрешённый Linux-хост через мастер SSH. Пока нет хоста, проверка безопасности не проводилась.",
    action: "Открыть подключение", href: "#host-form", tone: "neutral",
  };
  if (input.recoveryRequired) return {
    id: "recovery", title: "Проверьте прерванное изменение",
    detail: "Для выбранного хоста есть операция, требующая сверки и восстановления. Не запускайте новые изменения, пока не установлено фактическое состояние цели.",
    action: "Открыть восстановление", href: "#recent-remediations", tone: "critical",
  };
  if (!input.controlReady) return {
    id: "controller", title: "Проверьте управляющий узел",
    detail: "Готовность Ansible или inventory не подтверждена. Подготовьте управляющий узел перед локальными проверками.",
    action: "Открыть инструкцию", href: "/guide", tone: "attention",
  };
  if (input.activeJob) return {
    id: "running", title: "Проверка выполняется",
    detail: "Отслеживайте текущее задание и его журнал. Не принимайте решение о защищённости по предыдущему отчёту, пока новая проверка не завершилась.",
    action: "Перейти к заданию", href: "#ansible-actions", tone: "neutral",
  };
  const risk = input.riskSummary;
  const assessment = describeHostAuditEvidence({ alias, riskSummary: risk });
  if (assessment.state === "no_audit") {
    if (count(risk?.identityExcludedCount) > 0) return {
      id: "identity", title: "Уточните идентичность хоста",
      detail: "Исторические отчёты исключены из сводки после изменения идентичности актива или подключения. Проверьте хост и соберите новые доказательства.",
      action: "Проверить подключение", href: "#ansible-actions", tone: "attention",
    };
    return {
      id: "first_audit", title: "Запустите первый аудит безопасности",
      detail: "Сбор системных фактов и инвентаря не заменяет аудит. Выберите применимый профиль и инструмент; запуск выполняется только после вашего действия.",
      action: "Выбрать инструмент", href: "#ansible-actions", tone: "neutral",
    };
  }
  if (assessment.state === "stale") return {
    id: "repeat", title: "Обновите доказательства аудита",
    detail: "Подтверждённых свежих результатов нет. Повторите выбранные проверки с актуальными источниками; старые находки нельзя считать текущей картиной защищённости.",
    action: "Повторить проверку", href: "#ansible-actions", tone: "attention",
  };
  if (assessment.state === "needs_review") return {
    id: "coverage", title: "Разберите неполные результаты",
    detail: "Обнаружены неполные, устаревшие, исключённые по идентичности или противоречивые данные. Сверьте применимость профиля и состояние источников до выбора исправлений.",
    action: "Открыть сводку", href: `/reports/correlation/${encodeURIComponent(alias)}`, tone: "attention",
  };
  const observedFindings = ["critical", "high", "medium", "low", "unknown"]
    .reduce((sum, key) => sum + count(risk?.[key as keyof NonNullable<typeof risk>]), 0);
  if (observedFindings > 0) return {
    id: "triage", title: "Разберите наблюдаемые находки",
    detail: "Есть свежие результаты с находками. Проверьте технические доказательства, применимость и ограничения источников. План исправлений требует отдельного решения.",
    action: "Открыть находки", href: `/reports/correlation/${encodeURIComponent(alias)}`, tone: "attention",
  };
  return {
    id: "report", title: "Изучите свежий отчёт",
    detail: "В наблюдаемой области не зарегистрированы находки; это не означает отсутствие всех уязвимостей. Сохраните доказательства и настройте повторную проверку.",
    action: "Открыть сводку", href: `/reports/correlation/${encodeURIComponent(alias)}`, tone: "neutral",
  };
}
