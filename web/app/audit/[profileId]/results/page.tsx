import { notFound } from "next/navigation";
import { DemoHostCard } from "@/components/dashboard/demo-host-card";
import { FindingsExplorer } from "@/components/findings/findings-explorer";
import { SummaryCard } from "@/components/ui/summary-card";
import { getProfile } from "@/data/profiles";
import { createAuditReport } from "@/lib/demo-audit";

export default async function AuditResultsPage({ params }: { params: Promise<{ profileId: string }> }) {
  const { profileId } = await params;
  const profile = getProfile(profileId);

  if (!profile) {
    notFound();
  }

  const report = createAuditReport(profile.id);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Результаты аудита</h1>
        <p className="mt-2 text-slate-400">{profile.title} · найдено: {report.findings.length} · режим: демо</p>
      </div>
      <section className="rounded-md border border-sky-400/25 bg-sky-500/10 p-5">
        <h2 className="text-lg font-semibold text-white">Как читать результат</h2>
        <p className="mt-2 text-sm leading-6 text-slate-300">
          Сначала смотрите высокие и средние риски, затем источник проверки и рекомендацию. Кнопка перехода к
          исправлениям формирует план и демо-отчет, но не применяет изменения на Linux-хосте.
        </p>
      </section>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <SummaryCard label="Оценка защищенности" value={`${report.summary.score}%`} detail="Рассчитано по активным рискам" />
        <SummaryCard label="Высокий" value={report.summary.high} detail="Критичный приоритет исправления" />
        <SummaryCard label="Средний" value={report.summary.medium} detail="Требует планового действия" />
        <SummaryCard label="Низкий" value={report.summary.low} detail="Улучшение усиления" />
        <SummaryCard label="Инфо" value={report.summary.info} detail="Контекстные проверки" />
      </div>
      <DemoHostCard compact />
      <FindingsExplorer findings={report.findings} profileId={profile.id} />
    </div>
  );
}
