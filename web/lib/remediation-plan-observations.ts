import type { CorrelatedFinding } from "@/lib/audit-correlation";
import type { RemediationPlanItem } from "@/lib/state-store";

type PlanDecision = Pick<RemediationPlanItem, "status" | "riskAcceptedUntil">;

export function riskAcceptanceState(item: PlanDecision, now = Date.now()) {
  if (item.status !== "accepted_risk") return null;
  const until = Date.parse(item.riskAcceptedUntil ?? "");
  return !Number.isFinite(until) ? "unknown" as const : until <= now ? "expired" as const : "active" as const;
}

/** A historical confirmation or an expired exception cannot resolve a current
 * observation. Keep the saved decision unchanged and derive its present context. */
export function hasActivePlanDecision(item: PlanDecision, now = Date.now()) {
  return item.status !== "confirmed" && (item.status !== "accepted_risk" || riskAcceptanceState(item, now) === "active");
}

export function planObservationState(item: Pick<RemediationPlanItem, "status" | "riskAcceptedUntil" | "updatedAt">,
  current: CorrelatedFinding | undefined, now = Date.now()) {
  return {
    riskAcceptanceState: riskAcceptanceState(item, now),
    currentObservation: current ? {
      id: current.id, title: current.title, risk: current.risk, status: current.status,
      severityUnknown: current.severityUnknown, severityAssessment: current.severityAssessment ?? null,
      recurring: item.status === "confirmed" && current.sources.some((source) => Date.parse(source.createdAt ?? "") > Date.parse(item.updatedAt)),
      sources: current.sources.map((source) => ({ reportId: source.reportId, findingId: source.findingId,
        mode: source.mode, source: source.source, createdAt: source.createdAt })),
    } : null,
  };
}
