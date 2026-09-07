import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getReportsDir } from "@/lib/ansible-reports";
import { getRepoRoot } from "@/lib/ansible-control";
import {
  listOpenScapExceptions,
  listOpenScapPolicies,
  type OpenScapException,
  type OpenScapPolicy,
} from "@/lib/state-store";
import type { Finding } from "@/types";

type InventoryMembership = {
  groups: string[];
  children: Map<string, string[]>;
  knownGroups: Set<string>;
};

type OpenScapReport = {
  mode?: string;
  findings?: Finding[];
  summary?: Record<string, unknown>;
  scanner?: Record<string, unknown>;
};

function inventoryPath() {
  return path.join(getRepoRoot(), "ansible", "inventory.ini");
}

function inventoryMembership(target: string): InventoryMembership {
  const groups = new Set<string>();
  const children = new Map<string, string[]>();
  const knownGroups = new Set<string>();
  const filePath = inventoryPath();
  if (!existsSync(filePath)) return { groups: ["linux_hosts"], children, knownGroups };

  let currentGroup = "";
  let currentIsChildren = false;
  for (const rawLine of readFileSync(filePath, "utf8").split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const header = line.match(/^\[([^\]]+)]$/)?.[1];
    if (header) {
      currentIsChildren = header.endsWith(":children");
      currentGroup = header.replace(/:(?:vars|children)$/, "");
      knownGroups.add(currentGroup);
      continue;
    }
    if (!currentGroup || currentGroup !== currentGroup.trim() || line.includes("=")) {
      if (!currentIsChildren) {
        const alias = line.split(/\s+/, 1)[0];
        if (alias === target && currentGroup && !currentGroup.endsWith(":vars")) groups.add(currentGroup);
      }
      continue;
    }
    if (currentIsChildren) {
      const child = line.split(/\s+/, 1)[0];
      if (child) {
        const parents = children.get(child) ?? [];
        parents.push(currentGroup);
        children.set(child, parents);
      }
    } else {
      const alias = line.split(/\s+/, 1)[0];
      if (alias === target) groups.add(currentGroup);
    }
  }

  // `--limit` may be an inventory group. Treat that group as the intended
  // policy selector; reports for multi-host limits remain separate per host.
  if (!groups.size && knownGroups.has(target)) {
    groups.add(target);
  }

  const queue = [...groups];
  while (queue.length) {
    const child = queue.shift()!;
    for (const parent of children.get(child) ?? []) {
      if (!groups.has(parent)) {
        groups.add(parent);
        queue.push(parent);
      }
    }
  }
  groups.add("linux_hosts");
  return { groups: [...groups], children, knownGroups };
}

export function listInventoryGroups() {
  const filePath = inventoryPath();
  const groups = new Set<string>(["linux_hosts"]);
  if (!existsSync(filePath)) return [...groups];
  for (const rawLine of readFileSync(filePath, "utf8").split("\n")) {
    const group = rawLine.trim().match(/^\[([^\]]+)]$/)?.[1];
    if (!group || group.endsWith(":vars")) continue;
    groups.add(group.replace(/:children$/, ""));
  }
  return [...groups].sort((left, right) => left.localeCompare(right, "ru"));
}

export type ResolvedOpenScapPolicy = {
  groups: string[];
  policy: OpenScapPolicy | null;
  source: "group" | "environment";
};

export function resolveOpenScapPolicyForHost(target: string): ResolvedOpenScapPolicy {
  const { groups } = inventoryMembership(target);
  const policies = listOpenScapPolicies();
  const groupPolicies = policies.filter((policy) => policy.groupName !== "linux_hosts" && groups.includes(policy.groupName));
  if (groupPolicies.length > 1) {
    throw new Error(`Для цели ${target} найдено несколько OpenSCAP-профилей (${groupPolicies.map((policy) => policy.groupName).join(", ")}). Оставьте один профиль на пересекающиеся группы.`);
  }
  if (groupPolicies.length === 1) {
    return { groups, policy: groupPolicies[0], source: "group" };
  }
  const defaultPolicy = policies.find((policy) => policy.groupName === "linux_hosts") ?? null;
  return { groups, policy: defaultPolicy, source: defaultPolicy ? "group" : "environment" };
}

function ruleIdFromFinding(finding: Finding) {
  const fromEvidence = finding.evidence?.match(/(?:^|;\s*)rule=([^;\s]+)/)?.[1];
  return fromEvidence || finding.id.replace(/^openscap_/, "");
}

function activeExceptionForRule(exceptions: OpenScapException[], groups: string[], ruleId: string) {
  for (const groupName of groups) {
    const exception = exceptions.find((item) => item.groupName === groupName && item.ruleId === ruleId);
    if (exception) return exception;
  }
  return null;
}

function reportPath(reportId: string) {
  if (!/^[A-Za-z0-9_.:-]{1,160}$/.test(reportId)) return null;
  const directory = getReportsDir();
  const reportFile = path.join(directory, `${reportId}.json`);
  return reportFile.startsWith(`${directory}${path.sep}`) ? reportFile : null;
}

export function applyOpenScapExceptions({ hostAlias, reportId }: { hostAlias: string; reportId: string }) {
  const filePath = reportPath(reportId);
  if (!filePath || !existsSync(filePath)) return { applied: 0, policyGroup: null };
  const raw = JSON.parse(readFileSync(filePath, "utf8")) as OpenScapReport;
  if (raw.mode !== "openscap" || !Array.isArray(raw.findings)) return { applied: 0, policyGroup: null };

  const resolved = resolveOpenScapPolicyForHost(hostAlias);
  const now = Date.now();
  const activeExceptions = listOpenScapExceptions().filter((exception) => Date.parse(exception.expiresAt) > now);
  const matchingGroups = resolved.groups.sort((left, right) => (left === "linux_hosts" ? 1 : right === "linux_hosts" ? -1 : 0));
  const applied: Array<{ id: string; ruleId: string; groupName: string; expiresAt: string; reason: string }> = [];
  const findings = raw.findings.map((finding) => {
    if (finding.status !== "failed") return finding;
    const ruleId = ruleIdFromFinding(finding);
    const exception = activeExceptionForRule(activeExceptions, matchingGroups, ruleId);
    if (!exception) return finding;
    applied.push({ id: exception.id, ruleId, groupName: exception.groupName, expiresAt: exception.expiresAt, reason: exception.reason });
    return {
      ...finding,
      status: "manual" as const,
      title: `${finding.title} — согласованное исключение`,
      description: `${finding.description} Исключение действует до ${exception.expiresAt}.`,
      recommendation: `Исключение не устраняет риск. Причина: ${exception.reason}. Пересмотрите исключение до ${exception.expiresAt}.`,
      evidence: `${finding.evidence ?? ""}; exception_id=${exception.id}; exception_group=${exception.groupName}; exception_expires=${exception.expiresAt}`.slice(0, 3000),
    };
  });
  if (!applied.length) return { applied: 0, policyGroup: resolved.policy?.groupName ?? null };

  const failed = findings.filter((finding) => finding.status === "failed");
  raw.findings = findings;
  raw.summary = {
    ...(raw.summary ?? {}),
    high: failed.filter((finding) => finding.risk === "high").length,
    medium: failed.filter((finding) => finding.risk === "medium").length,
    low: failed.filter((finding) => finding.risk === "low").length,
    info: findings.filter((finding) => finding.risk === "info").length,
    total: findings.length,
  };
  raw.scanner = {
    ...(raw.scanner ?? {}),
    policyGroup: resolved.policy?.groupName ?? "environment",
    exceptionsApplied: applied,
  };
  writeFileSync(filePath, JSON.stringify(raw, null, 2), { mode: 0o600 });
  return { applied: applied.length, policyGroup: resolved.policy?.groupName ?? null };
}
