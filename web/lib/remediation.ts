import { randomUUID } from "node:crypto";
import {
  appendIncident,
  inventoryHostAddress,
  inventoryHostExists,
  isSafeLimit,
  reportIdForRun,
  runAnsiblePlaybook,
  type PlaybookAction,
} from "@/lib/ansible-control";
import {
  createRemediationTransaction,
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
  assertSingleKnownHost(hostAlias);
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
  assertSingleKnownHost(hostAlias);
  const transactionId = `txn-${new Date().toISOString().replace(/[-:.]/g, "")}-${randomUUID().slice(0, 8)}`;
  try {
    createRemediationTransaction({
      id: transactionId,
      hostAlias,
      action,
      profileId,
      reason,
      parameters: extraVars,
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
    updateRemediationTransaction(transactionId, { preAuditReportId });

    const backup = await runAnsiblePlaybook({
      action: "backupRemediation",
      profileId,
      limit: hostAlias,
      extraVars: { ...extraVars, transaction_id: transactionId, remediation_action: action },
    });
    const backupRef = backupReference(transactionId);
    updateRemediationTransaction(transactionId, { status: "backed_up", backupRef });

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
  if (transaction.status !== "applied") {
    throw Object.assign(new Error("Откат возможен только для успешно примененной транзакции."), { code: "rollback_not_available" });
  }
  if (confirmedHost !== transaction.hostAlias) {
    throw Object.assign(new Error("Для отката введите точный alias целевого хоста."), { code: "host_confirmation_required" });
  }
  const result = await runAnsiblePlaybook({
    action: "rollbackRemediation",
    profileId: transaction.profileId,
    limit: transaction.hostAlias,
    extraVars: { transaction_id: transaction.id, remediation_action: transaction.action },
  });
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
}

export function wouldBlockProtectedAddress(hostAlias: string, blockIp: string) {
  const protectedAddresses = new Set([
    inventoryHostAddress(hostAlias),
    ...((process.env.HCP_CONTROL_IPS ?? "").split(",").map((value) => value.trim()).filter(Boolean)),
  ]);
  return protectedAddresses.has(blockIp);
}
