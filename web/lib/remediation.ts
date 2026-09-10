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
}: {
  action: PlaybookAction;
  profileId: string;
  hostAlias: string;
  extraVars: Record<string, string>;
  reason: string;
}) {
  validateRemediationTarget(action, hostAlias, extraVars);
  const result = await runAnsiblePlaybook({
    action,
    profileId,
    limit: hostAlias,
    extraVars,
    checkMode: true,
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
}: {
  action: PlaybookAction;
  profileId: string;
  hostAlias: string;
  extraVars: Record<string, string>;
  reason: string;
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
    const preAudit = await runAnsiblePlaybook({ action: "agentlessAudit", profileId, limit: hostAlias });
    const preAuditReportId = reportIdForRun({
      action: "agentlessAudit",
      profileId,
      limit: hostAlias,
      reportRunId: preAudit.reportRunId,
    });
    const preAuditReport = preAuditReportId ? readAnsibleReport(preAuditReportId) : null;
    if (!preAuditReport || preAuditReport.partial) {
      throw new Error("Исходный аудит отсутствует или неполон. Изменения firewall не начаты.");
    }
    updateRemediationTransaction(transactionId, { preAuditReportId });

    assertConnectionUnchanged(hostAlias, connection);
    await runAnsiblePlaybook({
      action: "backupRemediation",
      profileId,
      limit: hostAlias,
      extraVars: { ...extraVars, transaction_id: transactionId, remediation_action: action },
    });
    const backupRef = backupReference(transactionId);
    updateRemediationTransaction(transactionId, { status: "backed_up", backupRef });

    assertConnectionUnchanged(hostAlias, connection);
    const applied = await runAnsiblePlaybook({ action, profileId, limit: hostAlias, extraVars });
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
    try {
      const postAudit = await runAnsiblePlaybook({ action: "agentlessAudit", profileId, limit: hostAlias });
      postAuditReportId = reportIdForRun({
        action: "agentlessAudit",
        profileId,
        limit: hostAlias,
        reportRunId: postAudit.reportRunId,
      });
      const postAuditReport = postAuditReportId ? readAnsibleReport(postAuditReportId) : null;
      if (!postAuditReport || postAuditReport.partial) {
        throw new Error("Повторный аудит отсутствует или неполон; изменение требует проверки.");
      }
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

export async function rollbackRemediation(transactionId: string, confirmedHost: string) {
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
