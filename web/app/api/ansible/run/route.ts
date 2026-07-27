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

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const action = body?.action;
  const profileId = normalizeProfileId(body?.profileId);
  const limit = body?.limit;
  const safeLimit = typeof limit === "string" ? limit : undefined;
  const confirmRun = body?.confirmResponse === true;

  if (!isPlaybookAction(action)) {
    return NextResponse.json(
      { ok: false, error: "unsupported_action", message: "Неподдерживаемый playbook." },
      { status: 400 },
    );
  }

  if (safeLimit && !isSafeLimit(safeLimit)) {
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
  if (requiresLimit && !safeLimit) {
    return NextResponse.json(
      {
        ok: false,
        error: "limit_required",
        message: "Выберите конкретный хост или группу в поле Limit.",
      },
      { status: 400 },
    );
  }

  if ((selected.kind === "response" || requiresConfirmation) && !confirmRun) {
    return NextResponse.json(
      {
        ok: false,
        error: "confirmation_required",
        message: selected.kind === "response"
          ? "Response-playbook требует явного подтверждения администратора."
          : "Эта проверка требует явного подтверждения администратора.",
      },
      { status: 400 },
    );
  }

  try {
    const { stdout, stderr, command, repoRoot, reportRunId } = await runAnsiblePlaybook({
      action,
      profileId,
      limit: safeLimit,
      extraVars: extraVars.values,
    });
    appendIncident({
      action,
      kind: selected.kind,
      status: "success",
      profileId,
      limit: safeLimit || null,
      message: selected.kind === "response" ? "Response-playbook выполнен." : "Проверка выполнена.",
      command,
    }, repoRoot);

    return NextResponse.json({
      ok: true,
      action,
      profileId,
      limit: safeLimit || null,
      reportRunId,
      reportId: reportIdForRun({ action, profileId, limit: safeLimit, reportRunId }),
      command,
      stdout,
      stderr,
    });
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string; code?: string };
    appendIncident({
      action,
      kind: selected.kind,
      status: "failed",
      profileId,
      limit: safeLimit || null,
      message: output.message ?? "Playbook завершился с ошибкой.",
    });
    return NextResponse.json(
      {
        ok: false,
        action,
        profileId,
        limit: safeLimit || null,
        command: "",
        message: output.message ?? "Playbook завершился с ошибкой.",
        stdout: output.stdout ?? "",
        stderr: output.stderr ?? "",
      },
      { status: output.code === "inventory_missing" ? 400 : 500 },
    );
  }
}
