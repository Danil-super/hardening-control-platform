export type RiskLevel = "high" | "medium" | "low" | "info";

export type FindingStatus = "failed" | "passed" | "fixed" | "manual";

export type FindingSource = "demo" | "agent" | "lynis" | "openscap" | "custom";

export type AuditProfile = {
  id: string;
  title: string;
  description: string;
  supportedOs: string[];
  categories: string[];
  rulesCount: number;
  severityFocus: RiskLevel[];
};

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

export type Remediation = {
  id: string;
  title: string;
  description: string;
  findingIds: string[];
  riskOfBreaking: "low" | "medium" | "high";
  supportedOs: string[];
  targetFiles: string[];
  backupRequired: boolean;
  rollbackAvailable: boolean;
  demoSteps: string[];
  realModeNotes: string;
};

export type AuditReport = {
  id: string;
  createdAt: string;
  profileId: string;
  mode: "demo" | "agent";
  summary: {
    high: number;
    medium: number;
    low: number;
    info: number;
    score: number;
  };
  findings: Finding[];
};

export type BackupRecord = {
  id: string;
  createdAt: string;
  remediationId: string;
  targetFiles: string[];
  status: "created" | "skipped";
  rollbackAvailable: boolean;
};

export type BeforeAfterReport = {
  before: AuditReport;
  after: AuditReport;
  appliedRemediations: Remediation[];
  backups: BackupRecord[];
  fixedFindings: Finding[];
  remainingFindings: Finding[];
  manualFindings: Finding[];
};
