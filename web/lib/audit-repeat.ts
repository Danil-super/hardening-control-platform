import {
  listAnsibleReports,
  readAnsibleReport,
  reportTimestamp,
  targetAliasFromReport,
} from "@/lib/ansible-reports";
import type { PlaybookAction } from "@/lib/ansible-control";
import type { RemediationTransaction } from "@/lib/state-store";

const reportModeByAction: Partial<Record<PlaybookAction, string>> = {
  collectFacts: "facts",
  agentlessAudit: "agentless",
  packageInventory: "packages",
  collectEvents: "events",
  sshCryptoAudit: "ssh-audit",
  networkPortScan: "nmap",
  lynisTemporaryAudit: "lynis",
  openScapAudit: "openscap",
  astraOvalAudit: "astra-oval",
};

export type AuditRepeatNotice = {
  reportId: string;
  reportCreatedAt: string;
  mode: string;
  message: string;
};

export type FindRepeatAuditNoticeInput = {
  action: PlaybookAction;
  profileId: string;
  hostAlias: string;
  extraVars: Record<string, string>;
  remediationTransactions: Pick<RemediationTransaction, "hostAlias" | "updatedAt">[];
};

function objectValue(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function nmapScope(reportId: string) {
  const report = readAnsibleReport(reportId);
  const scanner = objectValue(objectValue(report?.raw).scanner);
  return typeof scanner.scanScope === "string" ? scanner.scanScope : null;
}

function hasRecordedChangeAfter(reportTimestampValue: number, hostAlias: string, transactions: FindRepeatAuditNoticeInput["remediationTransactions"]) {
  return transactions.some((transaction) => {
    if (transaction.hostAlias !== hostAlias) return false;
    const changedAt = Date.parse(transaction.updatedAt);
    // If the timestamps cannot be reliably ordered, keep the safer path open:
    // do not tell the operator that a repeat audit is unnecessary.
    return Number.isFinite(changedAt) && changedAt >= reportTimestampValue;
  });
}

/**
 * Finds a completed equivalent audit that is still the latest known HCP
 * evidence for the host. This is intentionally a soft guard: manual changes,
 * database updates and control-profile updates are not observable here and
 * must always remain valid reasons to repeat a check.
 */
export function findRepeatAuditNotice(input: FindRepeatAuditNoticeInput): AuditRepeatNotice | null {
  const expectedMode = reportModeByAction[input.action];
  if (!expectedMode || !input.hostAlias || input.hostAlias.includes(",")) return null;

  const expectedNmapScope = input.action === "networkPortScan"
    ? input.extraVars.nmap_scan_scope ?? "top_100"
    : null;
  const previous = listAnsibleReports().find((report) => {
    if (!report.available || report.partial || !report.reportTimeValid) return false;
    if (report.mode !== expectedMode || targetAliasFromReport(report) !== input.hostAlias) return false;
    if (input.action === "agentlessAudit" && report.profileId !== input.profileId) return false;
    return input.action !== "networkPortScan" || nmapScope(report.id) === expectedNmapScope;
  });

  if (!previous) return null;
  const previousTimestamp = reportTimestamp(previous);
  if (!previousTimestamp || hasRecordedChangeAfter(previousTimestamp, input.hostAlias, input.remediationTransactions)) {
    return null;
  }

  return {
    reportId: previous.id,
    reportCreatedAt: previous.createdAt ?? previous.modifiedAt,
    mode: previous.mode,
    message: "Такая же завершённая проверка уже есть в истории. HCP не зафиксировала после неё операций изменения на этом хосте. Если настройки менялись вне HCP, обновилась база CVE или профиль проверки, либо нужна контрольная проверка, подтвердите повторный запуск.",
  };
}
