import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getReportsDir } from "@/lib/ansible-reports";
import { getInventoryHost, readStaticInventory } from "@/lib/inventory";
import { listOpenScapExceptions, listOpenScapPolicies, type OpenScapException, type OpenScapPolicy } from "@/lib/state-store";
import type { Finding } from "@/types";

type OpenScapReport = {
  inventoryHost?: string;
  mode?: string;
  findings?: Finding[];
  summary?: Record<string, unknown>;
  scanner?: Record<string, unknown>;
};

export function listInventoryGroups() {
  try { return readStaticInventory().groups.filter((group) => !["all", "ungrouped"].includes(group)); }
  catch (error) {
    if (!existsSync(path.resolve(process.cwd(), "..", "ansible", "inventory.ini"))) return [];
    throw error;
  }
}

export type ResolvedOpenScapPolicy = {
  groups: string[];
  policy: OpenScapPolicy | null;
  source: "group" | "environment";
};

export function selectOpenScapPolicy(target: string, groups: string[], policies: OpenScapPolicy[]): ResolvedOpenScapPolicy {
  const groupPolicies = policies.filter((policy) => policy.groupName !== "linux_hosts" && groups.includes(policy.groupName));
  if (groupPolicies.length > 1) {
    throw new Error(`Для хоста ${target} найдено несколько OpenSCAP-профилей (${groupPolicies.map((policy) => policy.groupName).join(", ")}). Оставьте один профиль на пересекающиеся группы.`);
  }
  const policy = groupPolicies[0] ?? policies.find((candidate) => candidate.groupName === "linux_hosts" && groups.includes("linux_hosts")) ?? null;
  return { groups, policy, source: policy ? "group" : "environment" };
}

export function resolveOpenScapPolicyForHost(target: string): ResolvedOpenScapPolicy {
  const host = getInventoryHost(target);
  if (!host || !host.groups.includes("linux_hosts")) {
    throw new Error("OpenSCAP требует точный alias одного хоста из linux_hosts. Группы и списки alias в ручном запуске не поддерживаются.");
  }
  return selectOpenScapPolicy(target, host.groups, listOpenScapPolicies());
}

function ruleIdFromFinding(finding: Finding) {
  const fromEvidence = finding.evidence?.match(/(?:^|;\s*)rule=([^;\s]+)/)?.[1];
  return fromEvidence || finding.id.replace(/^openscap_/, "");
}

export function annotateOpenScapExceptions(raw: OpenScapReport, groups: string[], exceptions: OpenScapException[], evaluatedAt: string) {
  if (raw.mode !== "openscap" || !Array.isArray(raw.findings)) throw new Error("Получен некорректный отчёт OpenSCAP.");
  const now = Date.parse(evaluatedAt);
  const active = exceptions.filter((exception) => groups.includes(exception.groupName) && Date.parse(exception.expiresAt) > now);
  const applied = new Map<string, OpenScapException>();
  const findings = raw.findings.map((finding) => {
    if (finding.source !== "openscap" || finding.status !== "failed") return finding;
    const matching = active.filter((item) => item.ruleId === ruleIdFromFinding(finding));
    if (!matching.length) return finding;
    for (const exception of matching) applied.set(exception.id, exception);
    return {
      ...finding,
      // Acceptance is a workflow annotation, not a successful control result.
      description: `${finding.description} Согласованное исключение: ${matching.map((item) => `${item.reason} (группа ${item.groupName}, до ${item.expiresAt})`).join("; ")}. Исходный результат проверки и риск сохранены.`,
    };
  });
  return {
    ...raw,
    findings,
    scanner: {
      ...(raw.scanner ?? {}),
      exceptionsEvaluatedAt: evaluatedAt,
      exceptionsApplied: [...applied.values()].map(({ id, ruleId, groupName, expiresAt, reason }) => ({ id, ruleId, groupName, expiresAt, reason })),
    },
  };
}

export function applyOpenScapExceptions({ hostAlias, reportId, resolved, exceptions }: {
  hostAlias: string;
  reportId: string;
  resolved?: ResolvedOpenScapPolicy;
  exceptions?: OpenScapException[];
}) {
  if (!/^[A-Za-z0-9_.:-]{1,240}$/.test(reportId)) throw new Error("Некорректный идентификатор отчёта OpenSCAP.");
  const filePath = path.join(getReportsDir(), `${reportId}.json`);
  if (!existsSync(filePath)) throw new Error("OpenSCAP не создал ожидаемый отчёт. Проверьте доступность хоста и inventory.");
  const raw = JSON.parse(readFileSync(filePath, "utf8")) as OpenScapReport;
  if (raw.inventoryHost !== hostAlias) throw new Error("Alias хоста не совпадает с результатом OpenSCAP; исключения не применены.");
  const selection = resolved ?? resolveOpenScapPolicyForHost(hostAlias);
  if (raw.scanner?.exceptionsEvaluatedAt) {
    return { applied: Array.isArray(raw.scanner.exceptionsApplied) ? raw.scanner.exceptionsApplied.length : 0, policyGroup: selection.policy?.groupName ?? null };
  }
  const report = annotateOpenScapExceptions(raw, selection.groups, exceptions ?? listOpenScapExceptions(), new Date().toISOString());
  const temporaryPath = `${filePath}.tmp`;
  writeFileSync(temporaryPath, JSON.stringify(report, null, 2), { mode: 0o600 });
  renameSync(temporaryPath, filePath);
  return { applied: report.scanner.exceptionsApplied.length, policyGroup: selection.policy?.groupName ?? null };
}
