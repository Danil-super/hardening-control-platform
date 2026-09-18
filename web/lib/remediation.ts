import { randomUUID } from "node:crypto";
import { networkInterfaces } from "node:os";
import { readAnsibleReport } from "@/lib/ansible-reports";
import {
  appendIncident,
  inventoryHostAddress,
  inventoryHostConnection,
  inventoryHostExists,
  isSafeLimit,
  reportIdForRun,
  runAnsiblePlaybook,
  validateExtraVars,
  type PlaybookAction,
} from "@/lib/ansible-control";
import {
  createRemediationTransaction,
  claimRemediationRollback,
  getRemediationTransaction,
  updateRemediationTransaction,
} from "@/lib/state-store";

export const reversibleRemediationActions = new Set<PlaybookAction>(["closePort", "blockIp"]);

export function isReversibleRemediationAction(action: PlaybookAction) {
  return reversibleRemediationActions.has(action);
}

type FirewallBaselineAssessment = {
  ok: boolean;
  blockers: string[];
  warnings: string[];
};

type AuditRawFinding = {
  id?: unknown;
  status?: unknown;
};

type AuditRawPayload = {
  scanner?: {
    available?: unknown;
    error?: unknown;
    incompleteChecks?: unknown;
  };
  findings?: unknown;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function incompleteCheckLabels(checks: string[]) {
  const labels: Record<string, string> = {
    ssh_effective_config: "эффективная конфигурация SSH",
    security_auto_updates: "наличие механизма security-обновлений",
    package_updates_available: "локальный кэш обновлений",
    world_writable_dirs: "права временных каталогов",
  };
  return checks.map((check) => labels[check] ?? check.replace(/_/g, " "));
}

/**
 * The full Linux profile deliberately keeps unrelated collection failures
 * visible.  They should not, however, prevent a reversible firewall operation
 * when the safety-critical evidence (current firewall and listening sockets)
 * was successfully collected and the operation itself verifies the backend
 * and creates a backup.
 */
export function assessFirewallBaseline(report: ReturnType<typeof readAnsibleReport>): FirewallBaselineAssessment {
  const blockers: string[] = [];
  const warnings: string[] = [];
  if (!report) {
    return { ok: false, blockers: ["исходный отчёт не создан или повреждён"], warnings };
  }
  if (report.available === false) blockers.push("исходный аудит недоступен");
  if (report.reportTimeValid === false) blockers.push("время исходного аудита некорректно");

  const raw = asRecord(report.raw) as AuditRawPayload | null;
  if (!raw) {
    if (report.partial) blockers.push("в отчёте нет сведений о проверках firewall и открытых портах");
    return { ok: blockers.length === 0, blockers, warnings };
  }

  const scanner = asRecord(raw.scanner) as AuditRawPayload["scanner"] | null;
  const incompleteChecks = Array.isArray(scanner?.incompleteChecks)
    ? scanner.incompleteChecks.filter((value): value is string => typeof value === "string")
    : [];
  if (scanner?.available === false || scanner?.error) blockers.push("исходный аудит завершился с ошибкой scanner");

  const findings = Array.isArray(raw.findings)
    ? raw.findings.filter((value): value is AuditRawFinding => Boolean(asRecord(value)))
    : [];
  const statusFor = (id: string) => findings.find((finding) => finding.id === id)?.status;
  const firewallStatus = statusFor("firewall_active");
  const portsUnavailable = statusFor("agentless_ports_unavailable");

  if (incompleteChecks.includes("firewall_active") || firewallStatus !== "passed") {
    blockers.push("не подтверждено активное состояние поддерживаемого firewall");
  }
  if (incompleteChecks.includes("open_ports") || portsUnavailable === "manual") {
    blockers.push("не получен список открытых портов перед изменением");
  }

  if (report.partial) {
    const unrelated = incompleteChecks.filter((check) => !["firewall_active", "open_ports"].includes(check));
    if (unrelated.length) {
      warnings.push(`Исходный аудит содержит несвязанные с firewall ограничения: ${incompleteCheckLabels(unrelated).join(", ")}.`);
    } else if (!blockers.length) {
      warnings.push("Исходный аудит отмечен как неполный, но состояние firewall и открытые порты подтверждены.");
    }
  }
  return { ok: blockers.length === 0, blockers, warnings };
}

function assertSingleKnownHost(limit: string) {
  if (!isSafeLimit(limit) || limit.includes(",") || !inventoryHostExists(limit)) {
    throw Object.assign(new Error("Для изменения выберите один сохраненный хост, а не группу или несколько хостов."), { code: "host_required" });
  }
}

function backupReference(transactionId: string) {
  return `/var/lib/hcp-backups/${transactionId}/firewall-state.tar.gz`;
}

function validateRemediationTarget(action: PlaybookAction, hostAlias: string, extraVars: Record<string, string>) {
  assertSingleKnownHost(hostAlias);
  if (!isReversibleRemediationAction(action)) throw new Error("Неподдерживаемое обратимое действие.");
  const validated = validateExtraVars(action, extraVars);
  if (!validated.ok) throw new Error(validated.message);
  const connection = inventoryHostConnection(hostAlias);
  if (action === "closePort" && extraVars.target_protocol !== "udp" && Number(extraVars.target_port) === connection.port) {
    throw Object.assign(new Error("Нельзя закрывать текущий SSH-порт управления хостом."), { code: "protected_ssh_port" });
  }
  if (action === "blockIp" && wouldBlockProtectedAddress(hostAlias, extraVars.block_ip)) {
    throw Object.assign(new Error("Нельзя блокировать адрес хоста или узла управления."), { code: "protected_address" });
  }
  return JSON.stringify(connection);
}

function assertConnectionUnchanged(hostAlias: string, expected: string) {
  assertSingleKnownHost(hostAlias);
  if (JSON.stringify(inventoryHostConnection(hostAlias)) !== expected) {
    throw Object.assign(new Error("SSH-подключение хоста изменилось после начала транзакции. Операция остановлена."), { code: "host_connection_changed" });
  }
}

export async function previewRemediation({
  action,
  profileId,
  hostAlias,
  extraVars,
  reason,
  becomePassword,
}: {
  action: PlaybookAction;
  profileId: string;
  hostAlias: string;
  extraVars: Record<string, string>;
  reason: string;
  becomePassword?: string;
}) {
  validateRemediationTarget(action, hostAlias, extraVars);
  const result = await runAnsiblePlaybook({
    action,
    profileId,
    limit: hostAlias,
    extraVars,
    checkMode: true,
    becomePassword,
  });
  appendIncident({
    action,
    kind: "system",
    status: "success",
    profileId,
    limit: hostAlias,
    message: `Сформирован dry-run remediation: ${reason}`,
    command: result.command,
  });
  return result;
}

export async function applyRemediation({
  action,
  profileId,
  hostAlias,
  extraVars,
  reason,
  becomePassword,
}: {
  action: PlaybookAction;
  profileId: string;
  hostAlias: string;
  extraVars: Record<string, string>;
  reason: string;
  becomePassword?: string;
}) {
  const connection = validateRemediationTarget(action, hostAlias, extraVars);
  const transactionId = `txn-${new Date().toISOString().replace(/[-:.]/g, "")}-${randomUUID().slice(0, 8)}`;
  try {
    createRemediationTransaction({
      id: transactionId,
      hostAlias,
      action,
      profileId,
      reason,
      parameters: { ...extraVars, _hcp_connection: connection },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Не удалось создать транзакцию remediation.";
    if (/remediation_transactions_active_host|UNIQUE constraint/i.test(message)) {
      throw Object.assign(new Error("Для этого хоста уже выполняется другое изменение. Дождитесь завершения текущей транзакции."), { code: "transaction_in_progress" });
    }
    throw error;
  }

  try {
    const preAudit = await runAnsiblePlaybook({ action: "agentlessAudit", profileId, limit: hostAlias, becomePassword });
    const preAuditReportId = reportIdForRun({
      action: "agentlessAudit",
      profileId,
      limit: hostAlias,
      reportRunId: preAudit.reportRunId,
    });
    const preAuditReport = preAuditReportId ? readAnsibleReport(preAuditReportId) : null;
    const preAuditAssessment = assessFirewallBaseline(preAuditReport);
    if (!preAuditAssessment.ok) {
      throw new Error(`Исходный аудит не подтверждает безопасную точку firewall: ${preAuditAssessment.blockers.join("; ")}. Изменения не начаты.`);
    }
    updateRemediationTransaction(transactionId, { preAuditReportId });

    assertConnectionUnchanged(hostAlias, connection);
    await runAnsiblePlaybook({
      action: "backupRemediation",
      profileId,
      limit: hostAlias,
      extraVars: { ...extraVars, transaction_id: transactionId, remediation_action: action },
      becomePassword,
    });
    const backupRef = backupReference(transactionId);
    updateRemediationTransaction(transactionId, { status: "backed_up", backupRef });

    assertConnectionUnchanged(hostAlias, connection);
    const applied = await runAnsiblePlaybook({ action, profileId, limit: hostAlias, extraVars, becomePassword });
    appendIncident({
      action,
      kind: "response",
      status: "success",
      profileId,
      limit: hostAlias,
      message: `Изменение применено в транзакции ${transactionId}: ${reason}`,
      command: applied.command,
      runId: transactionId,
    });
    let postAuditReportId: string | null = null;
    let postAuditError: string | null = null;
    let postAuditWarnings: string[] = [];
    try {
      const postAudit = await runAnsiblePlaybook({ action: "agentlessAudit", profileId, limit: hostAlias, becomePassword });
      postAuditReportId = reportIdForRun({
        action: "agentlessAudit",
        profileId,
        limit: hostAlias,
        reportRunId: postAudit.reportRunId,
      });
      const postAuditReport = postAuditReportId ? readAnsibleReport(postAuditReportId) : null;
      const postAuditAssessment = assessFirewallBaseline(postAuditReport);
      if (!postAuditAssessment.ok) {
        throw new Error(`Повторный аудит не подтвердил состояние firewall: ${postAuditAssessment.blockers.join("; ")}. Изменение требует проверки.`);
      }
      postAuditWarnings = postAuditAssessment.warnings;
      updateRemediationTransaction(transactionId, { status: "applied", postAuditReportId });
    } catch (error) {
      postAuditError = error instanceof Error ? error.message : "Повторный аудит не выполнен.";
      updateRemediationTransaction(transactionId, { status: "applied", error: postAuditError });
      appendIncident({
        action: "agentlessAudit",
        kind: "system",
        status: "failed",
        profileId,
        limit: hostAlias,
        message: `Изменение применено, но повторный аудит не выполнен: ${postAuditError}`,
        runId: transactionId,
      });
    }

    return {
      transaction: getRemediationTransaction(transactionId),
      result: applied,
      preAuditReportId,
      postAuditReportId,
      postAuditError,
      preAuditWarnings: preAuditAssessment.warnings,
      postAuditWarnings,
      backupRef,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Транзакция remediation завершилась с ошибкой.";
    updateRemediationTransaction(transactionId, { status: "failed", error: message });
    appendIncident({
      action,
      kind: "response",
      status: "failed",
      profileId,
      limit: hostAlias,
      message,
      runId: transactionId,
    });
    throw Object.assign(error instanceof Error ? error : new Error(message), { transactionId });
  }
}

export async function rollbackRemediation(transactionId: string, confirmedHost: string, becomePassword?: string) {
  const transaction = getRemediationTransaction(transactionId);
  if (!transaction) {
    throw Object.assign(new Error("Транзакция remediation не найдена."), { code: "transaction_not_found" });
  }
  if (!["applied", "failed", "rollback_failed"].includes(transaction.status) || !transaction.backupRef) {
    throw Object.assign(new Error("Откат доступен для завершённой или неуспешной транзакции с резервной копией."), { code: "rollback_not_available" });
  }
  if (confirmedHost !== transaction.hostAlias) {
    throw Object.assign(new Error("Для отката введите точный alias целевого хоста."), { code: "host_confirmation_required" });
  }
  if (!transaction.parameters._hcp_connection) {
    throw Object.assign(new Error("У старой транзакции нет снимка SSH-подключения. Проверьте резервную копию и выполните восстановление вручную."), { code: "legacy_backup_identity_missing" });
  }
  assertConnectionUnchanged(transaction.hostAlias, transaction.parameters._hcp_connection);
  claimRemediationRollback(transaction.id);
  try {
    const result = await runAnsiblePlaybook({
      action: "rollbackRemediation",
      profileId: transaction.profileId,
      limit: transaction.hostAlias,
      extraVars: { transaction_id: transaction.id, remediation_action: transaction.action },
      becomePassword,
    });
    // Do not call a failed reload successful: the runner propagates its exit code.
    updateRemediationTransaction(transaction.id, { status: "rolled_back", error: null });
    appendIncident({
      action: transaction.action,
      kind: "response",
      status: "success",
      profileId: transaction.profileId,
      limit: transaction.hostAlias,
      message: `Выполнен откат транзакции ${transaction.id}.`,
      command: result.command,
      runId: transaction.id,
    });
    return { result, transaction: getRemediationTransaction(transaction.id) };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Откат завершился ошибкой.";
    updateRemediationTransaction(transaction.id, { status: "rollback_failed", error: message });
    appendIncident({ action: transaction.action, kind: "response", status: "failed", profileId: transaction.profileId, limit: transaction.hostAlias, message, runId: transaction.id });
    throw error;
  }
}

export function wouldBlockProtectedAddress(hostAlias: string, blockIp: string) {
  const protectedAddresses = new Set([
    inventoryHostAddress(hostAlias),
    ...Object.values(networkInterfaces()).flatMap((interfaces) => (interfaces ?? []).map((item) => item.address)),
    ...((process.env.HCP_CONTROL_IPS ?? "").split(",").map((value) => value.trim()).filter(Boolean)),
  ]);
  return protectedAddresses.has(blockIp);
}
