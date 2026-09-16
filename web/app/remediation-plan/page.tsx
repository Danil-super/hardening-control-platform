import { RemediationPlanClient } from "@/components/remediation/remediation-plan-client";

export default async function RemediationPlanPage({ searchParams }: { searchParams: Promise<{ host?: string }> }) {
  const { host } = await searchParams;
  return <RemediationPlanClient initialHost={typeof host === "string" ? host : ""} />;
}
