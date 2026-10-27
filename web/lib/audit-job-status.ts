import type { AuditJob } from "@/lib/state-store";

export const isActiveAuditJob = (job: AuditJob) => job.status === "queued" || job.status === "running";
export const auditActionLabels: Record<string, string> = {
  ping: "Проверка подключения SSH", collectFacts: "Сведения о хосте", collectEvents: "События безопасности",
  agentlessAudit: "Локальные правила HCP", packageInventory: "Пакеты и CVE — Trivy", astraOvalAudit: "CVE Astra — OVAL",
  openScapAudit: "Конфигурация — OpenSCAP", sshCryptoAudit: "Безопасность SSH", networkPortScan: "Сканирование портов", lynisTemporaryAudit: "Lynis",
};
export const auditReportLabels: Record<string, string> = {
  agentless: "Локальные правила HCP", "astra-oval": "CVE Astra — OVAL", lynis: "Lynis", openscap: "Конфигурация — OpenSCAP",
  nmap: "Порты — Nmap", "ssh-audit": "Безопасность SSH", vulnerabilities: "CVE — Trivy", greenbone: "Greenbone",
};
export function completedAuditTransitions(previous: AuditJob[], next: AuditJob[]) {
  const running = new Set(previous.filter(isActiveAuditJob).map((job) => job.id));
  return next.filter((job) => !isActiveAuditJob(job) && running.has(job.id));
}
export function mergeAuditSnapshot(snapshot: AuditJob[], registeredAfterRequest: AuditJob[]) {
  const present = new Set(snapshot.map((job) => job.id));
  return [...registeredAfterRequest.filter((job) => !present.has(job.id)), ...snapshot];
}
export function auditCompletionMessage(job: AuditJob) {
  const state = job.status === "completed" ? "завершена" : job.status === "partial" ? "частичный результат" : job.status === "interrupted" ? "прервана" : "ошибка";
  const prefix = `${auditActionLabels[job.action] ?? job.action} · ${job.hostAlias}: ${state}.`;
  // A generic backend message provides no additional information.
  return job.result?.message && !/^Проверка (?:выполнена|завершена)\.?$/i.test(job.result.message.trim()) ? `${prefix} ${job.result.message}` : prefix;
}
