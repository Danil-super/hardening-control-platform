import { AgentImportClient } from "@/components/agent/agent-import-client";

export default function AgentImportPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Импорт результатов агента</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Получите отчет локального Linux-агента в режиме “только аудит” автоматически через промежуточный сервер или
          импортируйте JSON вручную. Это связывает реальный аудит хоста с веб-интерфейсом без изменения ОС.
        </p>
      </div>
      <AgentImportClient />
    </div>
  );
}
