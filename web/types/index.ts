export type RiskLevel = "high" | "medium" | "low" | "info";

export type FindingStatus = "failed" | "passed" | "fixed" | "manual";

export type FindingSource =
  | "agentless"
  | "custom"
  | "ssh_audit"
  | "nmap"
  | "lynis"
  | "openscap"
  | "trivy"
  | "greenbone"
  | "dependency_track";

export type Finding = {
  id: string;
  profileId: string;
  title: string;
  category: string;
  risk: RiskLevel;
  severityUnknown?: boolean;
  severityAssessment?: {
    level: "critical" | "high" | "medium" | "low";
    source: "oval_metadata" | "chromium_description" | "scanner_metadata";
  };
  status: FindingStatus;
  source: FindingSource;
  description: string;
  recommendation: string;
  remediationAvailable: boolean;
  remediationId?: string;
  affectedFiles?: string[];
  evidence?: string;
  lynis?: {
    ruleId: string;
    kind: "warning" | "suggestion";
    message: string;
    details: string;
    solution: string;
    rawRecord: string;
    reference: string;
    impact: string;
    explanationKnown: boolean;
    messageTranslated: boolean;
  };
};
