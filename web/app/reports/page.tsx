import { ReportsClient } from "@/components/reports/reports-client";

export default function ReportsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Отчеты</h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          Сравнительный демо-отчет “до/после” показывает исправленные проблемы, оставшиеся риски, ручные рекомендации и
          именованные записи резервных копий.
        </p>
      </div>
      <ReportsClient />
    </div>
  );
}
