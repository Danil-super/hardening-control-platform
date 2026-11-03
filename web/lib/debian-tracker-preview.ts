import { createHash } from "node:crypto";
import type { Finding } from "@/types";
import { readPinnedDebianTrackerFullSnapshot, type DebianTrackerFullManifest } from "@/lib/debian-tracker-snapshot";
import { evaluateDebianTrackerExcerpt, parseDebianTrackerExcerpt } from "@/lib/debian-tracker-crosscheck";

/** One verified full snapshot per report; never a network or host-changing operation. */
export type DebianTrackerPreview = {
  schemaVersion: 1;
  status: "provisional" | "unavailable";
  reason: string;
  candidateVerdict: "affected" | "fixed_or_not_affected" | "needs_review" | "unknown";
  trustedVerdict: "unknown";
  fullSnapshotSha256: string;
  derivedExcerptSha256: string | null;
  sourcePackage: string;
  sourceVersion: string;
  release: string;
  fixedVersion: string | null;
  capturedAt: string;
  pinMode: DebianTrackerFullManifest["pinMode"];
  conflictingWithTrivy: boolean;
  publisherAuthenticated: false;
  publisherFreshnessVerified: false;
  remediationAuthorized: false;
};
export type DebianTrackerPreviewSummary = {
  schemaVersion: 1;
  state: "enabled" | "invalid_pin" | "invalid_policy" | "unsupported_release" |
    "incomplete_inventory" | "unavailable" | "stale_snapshot" | "budget_exceeded";
  snapshotSha256: string | null;
  release: string | null;
  capturedAt: string | null;
  pinMode: DebianTrackerFullManifest["pinMode"] | null;
  eligibleFindings: number;
  annotatedFindings: number;
  candidateAffected: number;
  candidateFixed: number;
  candidateNeedsReview: number;
  candidateUnknown: number;
  conflictingWithTrivy: number;
  unavailable: number;
  note: string;
};

const SHA = /^[a-f0-9]{64}$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;
const SOURCE = /^[a-z0-9][a-z0-9+.-]*$/;
const VERSION = /^[A-Za-z0-9.+~:-]+$/;
const RELEASES: Record<string, string> = { "11": "bullseye", "12": "bookworm", "13": "trixie" };
const MAX_EVALUATIONS = 128;
const note = "Предварительная сверка с локальной полной базой Debian Security Tracker. " +
  "SHA-256 и локальное время получения не подтверждают издателя или свежесть базы. " +
  "Исходный статус Trivy, риск, охват и возможность исправления не изменяются.";

function summary(state: DebianTrackerPreviewSummary["state"], sha: string | null = null): DebianTrackerPreviewSummary {
  return { schemaVersion: 1, state, snapshotSha256: sha, release: null, capturedAt: null,
    pinMode: null, eligibleFindings: 0, annotatedFindings: 0, candidateAffected: 0,
    candidateFixed: 0, candidateNeedsReview: 0, candidateUnknown: 0,
    conflictingWithTrivy: 0, unavailable: 0, note };
}
function eligible(finding: Finding, osId: string, versionId: string): boolean {
  const cv = finding.cveApplicability;
  return !!cv && finding.source === "trivy" && CVE.test(cv.advisory.id)
    && cv.distribution.id === osId && cv.distribution.versionId === versionId
    && cv.package.manager === "dpkg"
    && cv.package.provenance === "distribution-maintainer"
    && cv.advisory.sourceMatch === "matched"
    && typeof cv.package.sourceName === "string" && cv.package.sourceName.length <= 180
    && SOURCE.test(cv.package.sourceName)
    && typeof cv.package.sourceVersion === "string" && cv.package.sourceVersion.length <= 256
    && VERSION.test(cv.package.sourceVersion);
}

/** Explicit SHA selection only; no refresh, fetch or writing during a scan. */
export function annotateDebianTrackerPreview(input: {
  findings: Finding[];
  stateRoot: string;
  osId: string;
  versionId: string;
  releaseCodename: string;
  inventoryComplete: boolean;
  snapshotSha256?: string;
  maxImportAgeHours?: number;
  now?: string;
}): { findings: Finding[]; summary: DebianTrackerPreviewSummary | null } {
  if (!input.snapshotSha256?.trim() || input.osId !== "debian") return { findings: input.findings, summary: null };
  const pin = input.snapshotSha256.trim();
  if (!SHA.test(pin)) return { findings: input.findings, summary: summary("invalid_pin") };
  const ageLimit = input.maxImportAgeHours ?? 168;
  if (!Number.isInteger(ageLimit) || ageLimit < 1 || ageLimit > 8760) {
    return { findings: input.findings, summary: summary("invalid_policy", pin) };
  }
  if (!Object.hasOwn(RELEASES, input.versionId) || RELEASES[input.versionId] !== input.releaseCodename) {
    return { findings: input.findings, summary: summary("unsupported_release", pin) };
  }
  if (input.inventoryComplete !== true) {
    return { findings: input.findings, summary: summary("incomplete_inventory", pin) };
  }
  const selected = input.findings.filter(f => eligible(f, input.osId, input.versionId));
  const distinct = new Set(selected.map(f => JSON.stringify([
    f.cveApplicability!.advisory.id,
    f.cveApplicability!.package.sourceName, f.cveApplicability!.package.sourceVersion,
  ])));
  const s = summary("enabled", pin);
  s.release = input.releaseCodename;
  s.eligibleFindings = selected.length;
  if (distinct.size > MAX_EVALUATIONS) {
    return { findings: input.findings, summary: { ...s, state: "budget_exceeded" } };
  }
  if (!distinct.size) return { findings: input.findings, summary: s };
  let snapshot: ReturnType<typeof readPinnedDebianTrackerFullSnapshot>;
  try { snapshot = readPinnedDebianTrackerFullSnapshot(input.stateRoot, pin); }
  catch { return { findings: input.findings, summary: { ...s, state: "unavailable" } }; }
  const manifest = snapshot.manifest;
  s.capturedAt = manifest.capturedAt;
  s.pinMode = manifest.pinMode;
  const assessedAt = Date.parse(input.now ?? new Date().toISOString());
  const age = (assessedAt - Date.parse(manifest.capturedAt)) / 3_600_000;
  if (!Number.isFinite(age) || age < -5 / 60 || age > ageLimit) {
    return { findings: input.findings, summary: { ...s, state: "stale_snapshot" } };
  }
  const cache = new Map<string, DebianTrackerPreview>();
  const findings = input.findings.map(f => {
    if (!eligible(f, input.osId, input.versionId)) return f;
    const cv = f.cveApplicability!;
    const sourceName = cv.package.sourceName!;
    const sourceVersion = cv.package.sourceVersion!;
    const key = JSON.stringify([cv.advisory.id, sourceName, sourceVersion]);
    let preview = cache.get(key);
    if (!preview) {
      let status: DebianTrackerPreview["status"] = "unavailable";
      let reason = "source_package_not_listed";
      let candidateVerdict: DebianTrackerPreview["candidateVerdict"] = "unknown";
      let derivedExcerptSha256: string | null = null;
      let fixedVersion: string | null = null;
      const pkg = Object.hasOwn(snapshot.data, sourceName) ? snapshot.data[sourceName] : null;
      if (pkg && typeof pkg === "object" && !Array.isArray(pkg)) {
        reason = "cve_not_listed_unknown_not_clean";
        if (Object.hasOwn(pkg, cv.advisory.id)) {
          try {
            const raw = JSON.stringify({ [sourceName]: { [cv.advisory.id]: (pkg as Record<string, unknown>)[cv.advisory.id] } });
            const digest = createHash("sha256").update(raw).digest("hex");
            const excerpt = parseDebianTrackerExcerpt(raw, digest);
            const evaluated = evaluateDebianTrackerExcerpt(excerpt, {
              osId: input.osId, inventoryComplete: true,
              cveId: cv.advisory.id, release: input.releaseCodename,
              sourcePackage: sourceName, sourceVersion,
            });
            status = evaluated.status;
            reason = evaluated.reason;
            candidateVerdict = evaluated.candidateVerdict;
            derivedExcerptSha256 = digest;
            fixedVersion = evaluated.fixedVersion;
          } catch { reason = "invalid_derived_excerpt"; }
        }
      }
      const conflictingWithTrivy = status === "provisional" && (
        (cv.verdict === "affected" && candidateVerdict === "fixed_or_not_affected")
        || (cv.verdict === "not_affected" && candidateVerdict === "affected")
      );
      preview = { schemaVersion: 1, status, reason, candidateVerdict,
        trustedVerdict: "unknown", fullSnapshotSha256: manifest.sha256,
        derivedExcerptSha256, sourcePackage: sourceName, sourceVersion,
        release: input.releaseCodename, fixedVersion, capturedAt: manifest.capturedAt,
        pinMode: manifest.pinMode, conflictingWithTrivy,
        publisherAuthenticated: false, publisherFreshnessVerified: false,
        remediationAuthorized: false };
      cache.set(key, preview);
    }
    s.annotatedFindings++;
    if (preview.candidateVerdict === "affected") s.candidateAffected++;
    else if (preview.candidateVerdict === "fixed_or_not_affected") s.candidateFixed++;
    else if (preview.candidateVerdict === "needs_review") s.candidateNeedsReview++;
    else s.candidateUnknown++;
    if (preview.status === "unavailable") s.unavailable++;
    if (preview.conflictingWithTrivy) s.conflictingWithTrivy++;
    return { ...f, debianTrackerPreview: preview };
  });
  return { findings, summary: s };
}
