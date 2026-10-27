import { getInventoryHost } from "@/lib/inventory";
import { assertAstraOvalProvenance, astraOvalApplicabilityIssue } from "@/lib/astra-oval-config";
import { listAstraOvalPolicies, type AstraOvalPolicy } from "@/lib/state-store";

export function selectAstraOvalPolicy(groups: string[], policies: AstraOvalPolicy[]) {
  const specific = policies.filter((policy) => policy.groupName !== "linux_hosts" && groups.includes(policy.groupName));
  if (specific.length > 1) throw new Error("Для хоста назначено несколько OVAL-баз через пересекающиеся группы. Оставьте одну подходящую базу.");
  const policy = specific[0] ?? policies.find((item) => item.groupName === "linux_hosts" && groups.includes("linux_hosts"));
  if (!policy) throw new Error("Назначьте OVAL-базу группе хоста на странице «Источники» → «CVE пакетов Astra».");
  assertAstraOvalProvenance(policy.config);
  return policy;
}

export function resolveAstraOvalPolicyForHost(alias: string) {
  const host = getInventoryHost(alias);
  if (!host || !host.groups.includes("linux_hosts")) throw new Error("Для OVAL-аудита выберите точный alias одного подключённого хоста Astra.");
  return selectAstraOvalPolicy(host.groups, listAstraOvalPolicies());
}

export function describeAstraOvalNextStep(alias: string, release: string | null) {
  try {
    const policy = resolveAstraOvalPolicyForHost(alias);
    const issue = astraOvalApplicabilityIssue(policy.config, release);
    return issue
      ? { ready: false, message: `OVAL-источник группы ${policy.groupName} уже сохранён. ${issue}`, href: "/data-sources#astra-oval-title" }
      : { ready: true, message: `OVAL-источник группы ${policy.groupName} уже назначен. Запустите «CVE Astra — OVAL / OpenSCAP»: проверка использует эту базу. Повторный сбор пакетов не нужен.`, href: "/hosts" };
  } catch (error) {
    return { ready: false, message: error instanceof Error ? error.message : "Проверьте назначение OVAL-базы группе хоста.", href: "/data-sources#astra-oval-title" };
  }
}
