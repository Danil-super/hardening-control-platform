import { getInventoryHost } from "@/lib/inventory";
import { listAstraOvalPolicies, type AstraOvalPolicy } from "@/lib/state-store";

export function selectAstraOvalPolicy(groups: string[], policies: AstraOvalPolicy[]) {
  const specific = policies.filter((policy) => policy.groupName !== "linux_hosts" && groups.includes(policy.groupName));
  if (specific.length > 1) throw new Error("Для хоста назначено несколько OVAL-баз через пересекающиеся группы. Оставьте одну подходящую базу.");
  const policy = specific[0] ?? policies.find((item) => item.groupName === "linux_hosts" && groups.includes("linux_hosts"));
  if (!policy) throw new Error("Назначьте OVAL-базу группе хоста на странице «Источники» → «CVE пакетов Astra».");
  return policy;
}

export function resolveAstraOvalPolicyForHost(alias: string) {
  const host = getInventoryHost(alias);
  if (!host || !host.groups.includes("linux_hosts")) throw new Error("Для OVAL-аудита выберите точный alias одного подключённого хоста Astra.");
  return selectAstraOvalPolicy(host.groups, listAstraOvalPolicies());
}
