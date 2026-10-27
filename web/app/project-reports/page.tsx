import { ProjectReportsClient } from "@/components/project-reports/project-reports-client";
import { getArchivedRecordIds } from "@/lib/state-store";

export const dynamic = "force-dynamic";

export default async function ProjectReportsPage({ searchParams }: { searchParams: Promise<{ host?: string | string[]; report?: string | string[]; view?: string }> }) {
  const query = await searchParams;
  const host = typeof query.host === "string" && /^[A-Za-z0-9_.:-]{1,96}$/.test(query.host) ? query.host : "";
  const report = typeof query.report === "string" && /^project_report_[a-f0-9-]{36}$/.test(query.report) ? query.report : "";
  return <ProjectReportsClient initialHostAlias={host} initialExportId={report} initialArchived={query.view === "archive" || Boolean(report && getArchivedRecordIds("pdf").has(report))} />;
}
