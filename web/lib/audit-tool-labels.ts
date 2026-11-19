export const auditToolLabels: Readonly<Record<string, string>> = {
  agentlessAudit: "Локальные правила HCP — Ansible",
  packageInventory: "Пакеты и CVE — Trivy",
  astraOvalAudit: "CVE Astra — OVAL / OpenSCAP",
  openScapAudit: "Профиль конфигурации — OpenSCAP",
  sshCryptoAudit: "Защита SSH — ssh-audit",
  lynisTemporaryAudit: "Рекомендации hardening — Lynis",
  networkPortScan: "Открытые TCP-порты — Nmap",
  ping: "Подключение SSH — Ansible",
  collectFacts: "Сведения о хосте — Ansible",
  collectEvents: "События безопасности — Ansible",
};
