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


/**
 * HCP's evidence-backed interpretation of an OS-package advisory. A Trivy
 * match is not equivalent to cryptographic proof of package origin.
 * Keep this independent of the generic check status (failed/passed/manual).
 */
export type CveApplicabilityAssessment = {
  schemaVersion: 1;
  verdict: "affected" | "not_affected" | "under_investigation" | "unknown";
  confidence: "metadata-consistent" | "unverified";
  reason: "scanner_affected" | "scanner_not_affected" | "vendor_review_required"
    | "unsupported_os_advisory" | "package_identity_ambiguous" | "package_identity_mismatch" | "package_not_in_inventory"
    | "package_origin_unverified" | "advisory_source_missing" | "advisory_source_mismatch"
    | "advisory_source_unsupported" | "scanner_status_unknown" | "database_not_fresh_or_verified";
  distribution: { id: string; versionId: string };
  package: {
    name: string; installedVersion: string; purl: string | null;
    manager: string | null; architecture: string | null;
    sourceName: string | null; sourceVersion: string | null;
    provenance: "distribution-maintainer" | "third-party" | "unknown";
  };
  advisory: {
    id: string; scannerStatus: string | null; dataSourceId: string | null;
    sourceMatch?: "matched" | "mismatch" | "missing" | "unsupported";
    dataSourceName: string | null; primaryUrl: string | null; fixedVersion: string | null;
  };
  database: {
    sha256: string | null; updatedAt: string | null; registration: string | null;
    freshness: "fresh" | "stale" | "missing" | "unknown";
  };
  assessedAt: string;
};

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
  cveApplicability?: CveApplicabilityAssessment;
  /** Operator-pinned OSV candidate only; never vendor-attested. */
  ubuntuOsvPreview?: {
    schemaVersion: 1;
    status: "provisional" | "unavailable";
    reason: string;
    candidateVerdict: "affected" | "fixed_or_not_affected" | "needs_review" | "unknown";
    trustedVerdict: "unknown";
    snapshotSha256: string;
    sourceRevision: string | null;
    sourcePackage: string;
    sourceVersion: string;
    conflictingWithTrivy: boolean;
    publisherAuthenticated: false;
    remediationAuthorized: false;
  };
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
