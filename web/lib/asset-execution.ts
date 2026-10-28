import { writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import { freezeInventoryTargets } from "@/lib/inventory";
import { assetPrivateKey, captureAssetTarget, networkAssetBinding } from "@/lib/asset-registry";
import type { AssetBinding, VerifiedAssetBinding } from "@/lib/asset-binding";
import { acquireAssetExecution, releaseAssetExecution } from "@/lib/state-store";

function booleanVariable(value: unknown) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && /^(true|yes|1|false|no|0)$/i.test(value)) return /^(true|yes|1)$/i.test(value);
  if (value === 0 || value === 1) return Boolean(value);
  throw new Error("В inventory ansible_become должен быть явным true/false.");
}

/** One resolved connection/trust snapshot serves both identity probe and run. */
export async function prepareAssetExecution(limit: string | undefined, options: {
  authenticate: boolean; remediationId?: string; expectedAssetBinding?: VerifiedAssetBinding;
}) {
  const frozen = freezeInventoryTargets(limit);
  let lease = "";
  try {
    const hosts: Record<string, Record<string, unknown>> = {};
    const groups: Record<string, { hosts: Record<string, object> }> = {};
    const bindings = new Map<string, AssetBinding>();
    const trust = new Map<string, { fingerprint: string; line: string }>();
    const algorithms = new Set<string>();
    for (const target of frozen.targets) {
      const { alias, connection, variables } = target;
      let binding: AssetBinding;
      if (options.authenticate) {
        const captured = await captureAssetTarget(alias, connection, options.expectedAssetBinding);
        binding = captured.binding;
        const endpoint = `${connection.address.toLowerCase()}\0${connection.port}`;
        const previous = trust.get(endpoint);
        if (previous && previous.fingerprint !== captured.observation.sshHostKeyFingerprint) throw new Error("Один SSH endpoint сменил ключ во время подготовки группы. Запуск остановлен.");
        trust.set(endpoint, { fingerprint: captured.observation.sshHostKeyFingerprint, line: captured.observation.hostKeyLine });
        for (const algorithm of captured.observation.hostKeyAlgorithms.split(",")) algorithms.add(algorithm);
      } else binding = networkAssetBinding(alias, connection);
      bindings.set(alias, binding);
      const python = variables.ansible_python_interpreter ?? "/usr/bin/python3";
      if (typeof python !== "string" || !/^(?:\/[A-Za-z0-9_.+-]+)+$/.test(python)) throw new Error("Укажите явный абсолютный путь ansible_python_interpreter.");
      if (variables.ansible_become_method != null && variables.ansible_become_method !== "sudo") throw new Error("Поддерживается проверяемое повышение прав через sudo.");
      const becomeUser = variables.ansible_become_user ?? "root";
      if (typeof becomeUser !== "string" || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(becomeUser)) throw new Error("Недопустимый пользователь повышения прав.");
      hosts[alias] = { ansible_host: connection.address, ansible_port: connection.port,
        ...(connection.user ? { ansible_user: connection.user } : {}),
        ...(options.authenticate ? { ansible_connection: "ssh", ansible_ssh_private_key_file: assetPrivateKey(alias, connection) } : {}),
        ...(variables.ansible_become === undefined ? {} : { ansible_become: booleanVariable(variables.ansible_become) }),
        ansible_become_method: "sudo", ansible_become_user: becomeUser, ansible_python_interpreter: python };
      for (const group of target.groups.filter((name) => !["all", "ungrouped"].includes(name))) {
        groups[group] ??= { hosts: {} }; groups[group].hosts[alias] = {};
      }
    }
    const knownHostsPath = path.join(frozen.directory, "known_hosts");
    writeFileSync(knownHostsPath, [...trust.values()].map((item) => item.line).join("\n") + "\n", { mode: 0o600 });
    writeFileSync(frozen.inventoryPath, JSON.stringify({ all: { hosts, children: groups } }), { mode: 0o600 });
    lease = acquireAssetExecution([...bindings].map(([alias, binding]) => ({ alias, binding: binding.status === "verified" ? binding : null })), options.remediationId);
    return { inventoryPath: frozen.inventoryPath, bindings, sshTrust: options.authenticate ? { knownHostsPath, algorithms: [...algorithms].join(",") } : undefined,
      release: () => { if (lease) releaseAssetExecution(lease); rmSync(frozen.directory, { recursive: true, force: true }); } };
  } catch (error) {
    if (lease) releaseAssetExecution(lease);
    rmSync(frozen.directory, { recursive: true, force: true });
    throw error;
  }
}
