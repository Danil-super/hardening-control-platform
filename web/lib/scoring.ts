import type { Finding, RiskLevel } from "@/types";

export const riskWeights: Record<RiskLevel, number> = {
  high: 20,
  medium: 10,
  low: 4,
  info: 1,
};

export function countRisks(findings: Finding[]) {
  return findings.reduce(
    (summary, finding) => {
      if (finding.status !== "passed" && finding.status !== "fixed") {
        summary[finding.risk] += 1;
      }
      return summary;
    },
    { high: 0, medium: 0, low: 0, info: 0 } as Record<RiskLevel, number>,
  );
}

export function calculateScore(findings: Finding[]) {
  const penalty = findings.reduce((total, finding) => {
    if (finding.status === "passed" || finding.status === "fixed") {
      return total;
    }
    return total + riskWeights[finding.risk];
  }, 0);

  return Math.max(0, Math.min(100, 100 - penalty));
}

export function buildSummary(findings: Finding[]) {
  const risks = countRisks(findings);
  return {
    ...risks,
    score: calculateScore(findings),
  };
}
