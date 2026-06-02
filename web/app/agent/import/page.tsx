import { AgentImportClient } from "@/components/agent/agent-import-client";

export default function AgentImportPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Реальный audit-only аудит</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Получите отчет локального Linux-агента автоматически через bridge или импортируйте JSON вручную. Этот сценарий
          проверяет реальный хост, но не применяет исправления и не меняет ОС.
        </p>
      </div>
      <AgentImportClient />
    </div>
  );
}
