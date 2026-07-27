export type RiskLevel = "high" | "medium" | "low" | "info";

export type FindingStatus = "failed" | "passed" | "fixed" | "manual";

export type FindingSource = "agentless" | "custom" | "ssh_audit" | "nmap" | "lynis";

export type Finding = {
  id: string;
  profileId: string;
  title: string;
  category: string;
  risk: RiskLevel;
  status: FindingStatus;
  source: FindingSource;
  description: string;
  recommendation: string;
  remediationAvailable: boolean;
  remediationId?: string;
  affectedFiles?: string[];
  evidence?: string;
};
