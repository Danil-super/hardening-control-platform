import { NextResponse } from "next/server";
import {
  isPlaybookAction,
  isSafeLimit,
  normalizeProfileId,
  playbooks,
  validateExtraVars,
} from "@/lib/ansible-control";
import { findRepeatAuditNotice } from "@/lib/audit-repeat";
import { listRemediationTransactions } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * Lightweight preflight used by the browser before it sends a one-time sudo
 * password to the actual audit endpoint. POST /run repeats this check so API
 * callers and races cannot silently bypass the confirmation.
 */
export function GET(request: Request) {
  const url = new URL(request.url);
  const action = url.searchParams.get("action");
  const limit = url.searchParams.get("limit")?.trim() ?? "";
  const profileId = normalizeProfileId(url.searchParams.get("profileId"));

  if (!isPlaybookAction(action) || ("internal" in playbooks[action] && playbooks[action].internal) || playbooks[action].kind !== "audit") {
    return NextResponse.json({ ok: false, error: "unsupported_action", message: "Неподдерживаемая проверка." }, { status: 400 });
  }
  if (!limit || !isSafeLimit(limit) || limit.includes(",")) {
    return NextResponse.json({ ok: false, error: "host_required", message: "Выберите один конкретный хост для проверки." }, { status: 400 });
  }

  const extraVars = validateExtraVars(action, action === "networkPortScan"
    ? { nmap_scan_scope: url.searchParams.get("nmapScanScope") ?? undefined }
    : {});
  if (!extraVars.ok) {
    return NextResponse.json({ ok: false, error: "bad_extra_vars", message: extraVars.message }, { status: 400 });
  }

  const repeatAudit = findRepeatAuditNotice({
    action,
    profileId,
    hostAlias: limit,
    extraVars: extraVars.values,
    remediationTransactions: listRemediationTransactions(500),
  });
  return NextResponse.json({ ok: true, repeatAudit });
}
