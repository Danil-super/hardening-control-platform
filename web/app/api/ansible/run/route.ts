import { NextResponse } from "next/server";
import {
  appendIncident,
  isPlaybookAction,
  isSafeLimit,
  normalizeProfileId,
  playbooks,
  reportIdForRun,
  runAnsiblePlaybook,
  validateExtraVars,
} from "@/lib/ansible-control";
import { applyOpenScapExceptions, resolveOpenScapPolicyForHost } from "@/lib/openscap-policy";
import { resolveAstraOvalPolicyForHost } from "@/lib/astra-oval-policy";
import { inspectAuditReports } from "@/lib/audit-result";
import { readAnsibleReport } from "@/lib/ansible-reports";
import { listOpenScapExceptions } from "@/lib/state-store";
import {
  applyRemediation,
  isReversibleRemediationAction,
  previewRemediation,
} from "@/lib/remediation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function validReason(value: unknown): value is string {
  return typeof value === "string" && value.trim().length >= 10 && value.trim().length <= 500;
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const action = body?.action;
  const profileId = normalizeProfileId(body?.profileId);
  const limit = typeof body?.limit === "string" ? body.limit.trim() : "";
  const mode = body?.mode === "preview" ? "preview" : "apply";

  if (!isPlaybookAction(action) || ("internal" in playbooks[action] && playbooks[action].internal)) {
    return NextResponse.json(
      { ok: false, error: "unsupported_action", message: "Неподдерживаемый playbook." },
      { status: 400 },
    );
  }

  if (limit && !isSafeLimit(limit)) {
    return NextResponse.json(
      { ok: false, error: "bad_limit", message: "Limit может содержать только имена хостов/групп без пробелов." },
      { status: 400 },
    );
  }

  const extraVars = validateExtraVars(action, body?.extraVars);
  if (!extraVars.ok) {
    return NextResponse.json(
      { ok: false, error: "bad_extra_vars", message: extraVars.message },
      { status: 400 },
    );
  }

  const selected = playbooks[action];
  const requiresLimit = "requiresLimit" in selected && selected.requiresLimit === true;
  const requiresConfirmation = "requiresConfirmation" in selected && selected.requiresConfirmation === true;
  if (requiresLimit && !limit) {
    return NextResponse.json(
      { ok: false, error: "limit_required", message: "Выберите конкретный хост или группу в поле Limit." },
      { status: 400 },
    );
  }

  if (selected.kind === "response") {
    if (!isReversibleRemediationAction(action)) {
      return NextResponse.json(
        { ok: false, error: "transaction_required", message: "Доступны только обратимые remediation-действия с резервной копией и откатом." },
        { status: 400 },
      );
    }
    if (!validReason(body?.reason)) {
      return NextResponse.json(
        { ok: false, error: "reason_required", message: "Укажите причину изменения не короче 10 символов." },
        { status: 400 },
      );
    }
    if (typeof body?.confirmedHost !== "string" || body.confirmedHost.trim() !== limit) {
      return NextResponse.json(
        { ok: false, error: "host_confirmation_required", message: "Для изменения введите точный alias целевого хоста." },
        { status: 400 },
      );
    }
    try {
      if (mode === "preview") {
        const preview = await previewRemediation({
          action,
          profileId,
          hostAlias: limit,
          extraVars: extraVars.values,
          reason: body.reason.trim(),
        });
        return NextResponse.json({
          ok: true,
          mode,
          action,
          profileId,
          limit,
          message: "Dry-run завершен: изменения на хост не применялись.",
          command: preview.command,
          stdout: preview.stdout,
          stderr: preview.stderr,
        });
      }

      const applied = await applyRemediation({
        action,
        profileId,
        hostAlias: limit,
        extraVars: extraVars.values,
        reason: body.reason.trim(),
      });
      const postAudit = applied.postAuditReportId ? readAnsibleReport(applied.postAuditReportId) : null;
      const partial = Boolean(applied.postAuditError || !postAudit || postAudit.partial);
      return NextResponse.json({
        ok: true,
        partial,
        mode,
        action,
        profileId,
        limit,
        message: applied.postAuditError
          ? `Изменение применено, но повторный аудит завершился ошибкой: ${applied.postAuditError}`
          : partial ? "Изменение применено и резервная копия создана, но повторный аудит неполный. Проверьте ограничения отчёта."
            : "Изменение применено: резервная копия создана, повторный аудит выполнен.",
        transaction: applied.transaction,
        preAuditReportId: applied.preAuditReportId,
        postAuditReportId: applied.postAuditReportId,
        backupRef: applied.backupRef,
        command: applied.result.command,
        stdout: applied.result.stdout,
        stderr: applied.result.stderr,
      });
    } catch (error) {
      const output = error as { stdout?: string; stderr?: string; message?: string; transactionId?: string };
      return NextResponse.json(
        {
          ok: false,
          action,
          profileId,
          limit,
          transactionId: output.transactionId ?? null,
          message: output.message ?? "Транзакция remediation завершилась с ошибкой.",
          stdout: output.stdout ?? "",
          stderr: output.stderr ?? "",
        },
        { status: 400 },
      );
    }
  }

  if (requiresConfirmation && body?.confirmAudit !== true) {
    return NextResponse.json(
      { ok: false, error: "confirmation_required", message: "Эта проверка требует явного подтверждения администратора." },
      { status: 400 },
    );
  }

  let runnerExtraVars = extraVars.values;
  if (action === "astraOvalAudit") {
    try {
      const policy = resolveAstraOvalPolicyForHost(limit);
      runnerExtraVars = { hcp_oval_config: JSON.stringify(policy.config) };
    } catch (error) {
      return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось выбрать OVAL-базу." }, { status: 400 });
    }
  }
  let openScapPolicy: ReturnType<typeof resolveOpenScapPolicyForHost> | null = null;
  let openScapExceptions: ReturnType<typeof listOpenScapExceptions> = [];
  if (action === "openScapAudit" && limit) {
    try {
      openScapPolicy = resolveOpenScapPolicyForHost(limit);
      openScapExceptions = listOpenScapExceptions();
      if (openScapPolicy.policy) {
        runnerExtraVars = {
          ...runnerExtraVars,
          hcp_openscap_datastream: openScapPolicy.policy.datastream,
          hcp_openscap_profile: openScapPolicy.policy.profile,
          hcp_openscap_policy_group: openScapPolicy.policy.groupName,
        };
      }
    } catch (error) {
      return NextResponse.json(
        { ok: false, error: "openscap_policy_ambiguous", message: error instanceof Error ? error.message : "Не удалось выбрать OpenSCAP-профиль." },
        { status: 400 },
      );
    }
  }

  try {
    const { stdout, stderr, command, reportRunId } = await runAnsiblePlaybook({
      action,
      profileId,
      limit: limit || undefined,
      extraVars: runnerExtraVars,
    });
    const reportId = reportIdForRun({ action, profileId, limit, reportRunId });
    let exceptionsApplied = 0;
    let policyWarning: string | null = null;
    if (action === "openScapAudit" && limit && reportId) {
      try {
        exceptionsApplied = applyOpenScapExceptions({ hostAlias: limit, reportId, resolved: openScapPolicy ?? undefined, exceptions: openScapExceptions }).applied;
      } catch (error) {
        policyWarning = `Не удалось учесть исключения OpenSCAP: ${error instanceof Error ? error.message : "неизвестная ошибка"}`;
      }
    }
    const outcome = inspectAuditReports({ action, profileId, limit, reportRunId });
    if (policyWarning) { outcome.partial = true; outcome.warnings.push(policyWarning); }
    const auditMessage = (action === "openScapAudit"
      ? `${openScapPolicy?.policy ? `OpenSCAP: профиль группы ${openScapPolicy.policy.groupName}.` : "OpenSCAP: использована конфигурация окружения."}${exceptionsApplied ? ` Применено исключений: ${exceptionsApplied}.` : ""}`
      : "Проверка выполнена.") + (outcome.partial ? ` Проверка неполная: ${outcome.warnings.join(" ")}` : "");
    appendIncident({
      action,
      kind: "audit",
      status: outcome.partial ? "failed" : "success",
      profileId,
      limit: limit || null,
      message: auditMessage,
      command,
    });

    return NextResponse.json({
      ok: true,
      action,
      profileId,
      limit: limit || null,
      reportRunId,
      reportId,
      reportIds: outcome.reportIds,
      partial: outcome.partial,
      warnings: outcome.warnings,
      message: auditMessage,
      openScapPolicy: openScapPolicy?.policy ? {
        groupName: openScapPolicy.policy.groupName,
        datastream: openScapPolicy.policy.datastream,
        profile: openScapPolicy.policy.profile,
      } : null,
      exceptionsApplied,
      command,
      stdout,
      stderr,
    });
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string; code?: string };
    appendIncident({
      action,
      kind: "audit",
      status: "failed",
      profileId,
      limit: limit || null,
      message: output.message ?? "Playbook завершился с ошибкой.",
    });
    return NextResponse.json(
      {
        ok: false,
        action,
        profileId,
        limit: limit || null,
        command: "",
        message: output.message ?? "Playbook завершился с ошибкой.",
        stdout: output.stdout ?? "",
        stderr: output.stderr ?? "",
      },
      { status: output.code === "inventory_missing" ? 400 : 500 },
    );
  }
}
