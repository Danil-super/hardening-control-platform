import type { BeforeAfterReport } from "@/types";

export function serializeReport(report: BeforeAfterReport) {
  return JSON.stringify(report, null, 2);
}

export function getReportDelta(report: BeforeAfterReport) {
  return {
    high: report.before.summary.high - report.after.summary.high,
    medium: report.before.summary.medium - report.after.summary.medium,
    low: report.before.summary.low - report.after.summary.low,
    info: report.before.summary.info - report.after.summary.info,
    score: report.after.summary.score - report.before.summary.score,
  };
}
