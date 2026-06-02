import { Terminal } from "lucide-react";

const auditRequest = `POST /agent/audit
{
  "profileId": "basic_linux",
  "mode": "audit_only"
}`;

const auditResponse = `{
  "auditId": "audit_001",
  "hostname": "ubuntu-server",
  "os": "Ubuntu 24.04",
  "findings": [],
  "summary": {
    "high": 3,
    "medium": 7,
    "low": 5,
    "score": 68
  }
}`;

const remediateRequest = `POST /agent/remediate
{
  "auditId": "audit_001",
  "remediationIds": ["disable_ssh_root_login", "enable_ufw"],
  "createBackup": true
}`;

export default function AgentPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Будущий локальный Linux Agent</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          В первой версии агент не меняет систему. Эта страница фиксирует будущий контракт для Ubuntu/Debian,
          Lynis, OpenSCAP, backup, remediation и rollback.
        </p>
      </div>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <Terminal size={22} className="text-sky-200" aria-hidden="true" />
          <h2 className="mt-4 text-xl font-semibold text-white">Предполагаемый запуск</h2>
          <pre className="mt-4 overflow-x-auto rounded-md bg-slate-900 p-4 text-sm text-slate-200">
            <code>{`python3 agent.py audit --profile basic_linux
python3 agent.py remediate --audit audit_001 --remediation disable_ssh_root_login
python3 agent.py rollback --backup backup_2026_06_02_001`}</code>
          </pre>
        </div>

        <div className="rounded-md border border-slate-800 bg-slate-950/70 p-5">
          <h2 className="text-xl font-semibold text-white">Будущие возможности</h2>
          <ul className="mt-4 space-y-3 text-sm text-slate-300">
            <li>Определение ОС через /etc/os-release</li>
            <li>Запуск Lynis и парсинг результатов</li>
            <li>OpenSCAP как дополнительный модуль соответствия требованиям</li>
            <li>YAML-правила для пользовательских проверок</li>
            <li>Менеджер резервных копий, исправлений и отката</li>
          </ul>
        </div>
      </section>

      <section className="grid gap-5 lg:grid-cols-3">
        {[auditRequest, auditResponse, remediateRequest].map((code, index) => (
          <pre key={index} className="overflow-x-auto rounded-md border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-200">
            <code>{code}</code>
          </pre>
        ))}
      </section>
    </div>
  );
}
