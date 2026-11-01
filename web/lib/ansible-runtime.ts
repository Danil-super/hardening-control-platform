import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { assessTargetPython } from "@/lib/host-readiness";

const execFileAsync = promisify(execFile);

export type AnsibleRuntime = {
  id: "modern" | "legacy";
  ansible: string;
  playbook: string;
  coreVersion: string;
};
export type TargetPythonObservation = { alias: string; pythonVersion: string | null };

export function hasModernAnsibleRuntime() {
  return Boolean(process.env.HCP_ANSIBLE_MODERN_BIN_DIR);
}

function runtimeCandidates() {
  const modern = process.env.HCP_ANSIBLE_MODERN_BIN_DIR;
  if (modern && (!path.isAbsolute(modern) || /[\0\r\n]/.test(modern))) {
    throw new Error("HCP_ANSIBLE_MODERN_BIN_DIR должен быть абсолютным путём к установленному Ansible.");
  }
  return [
    ...(modern ? [{ id: "modern" as const, ansible: path.join(modern, "ansible"), playbook: path.join(modern, "ansible-playbook") }] : []),
    { id: "legacy" as const, ansible: "ansible", playbook: "ansible-playbook" },
  ];
}

/** Probe the installed program, not the container tag or a configured version. */
async function inspectRuntime(candidate: Omit<AnsibleRuntime, "coreVersion">) {
  try {
    const result = await execFileAsync(candidate.ansible, ["--version"], {
      timeout: 10_000, maxBuffer: 64 * 1024,
      // Ansible rejects the POSIX C locale before printing its version. The
      // Debian control image provides C.UTF-8, including in minimal installs.
      env: { ...process.env, LC_ALL: "C.UTF-8", ANSIBLE_FORCE_COLOR: "false" },
    });
    const coreVersion = result.stdout.match(/^ansible\s+\[core\s+(\d+\.\d+\.\d+)\]/m)?.[1];
    return coreVersion ? { ...candidate, coreVersion } : null;
  } catch {
    // Controller diagnostics may contain local paths; expose only availability.
    return null;
  }
}

/** One playbook process must support every frozen target; never change Python. */
export async function selectAnsibleRuntime(targets: readonly TargetPythonObservation[]): Promise<AnsibleRuntime> {
  if (!targets.length) throw new Error("Для выбора Ansible требуется версия Python каждого целевого хоста.");
  const candidates = runtimeCandidates();
  const runtimes = await Promise.all(candidates.map(inspectRuntime));
  for (const runtime of runtimes) {
    if (runtime && targets.every((target) => assessTargetPython(target.pythonVersion, runtime.coreVersion).compatible === true)) return runtime;
  }
  const targetSummary = targets.map((target) => `${target.alias}: Python ${target.pythonVersion ?? "не определён"}`).join("; ");
  const available = candidates.map((candidate, index) => `${candidate.id}: ${runtimes[index]?.coreVersion ?? "версия недоступна"}`).join(", ");
  throw Object.assign(new Error(`Нет установленного Ansible с подтверждённой совместимостью для всех выбранных хостов (${targetSummary}). Исполнители: ${available}. Разделите несовместимые версии Python на отдельные запуски или установите совместимый исполнитель на control node; системный Python серверов не изменяется.`), {
    code: "ansible_runtime_incompatible",
  });
}
