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
