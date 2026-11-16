/** Evidence integrity checks for Astra OVAL report summaries.
 *
 * A selected vendor feed can contain tens of thousands of definitions. The
 * summary must never call truncated/unknown scanner output a completed clean
 * result. This is a local consistency check, NOT publisher authentication,
 * independent verification of CVEs or a replacement for the original XML.
 */
export type AstraOvalEvidenceStatus = {
  complete: boolean;
  reason: string;
  definitionCount: number | null;
};

type RecordLike = Record<string, unknown>;
const SHA = /^[a-f0-9]{64}$/i;
const OVAL_ID = /^oval:[a-zA-Z0-9_.:-]{3,200}$/;
const MAX_DEFINITIONS = 30_000;
const COMPLETED_STATES = new Set(["true", "false", "not applicable"]);
const record = (value: unknown): RecordLike | null => value && typeof value === "object" && !Array.isArray(value)
  ? value as RecordLike : null;

export function assessAstraOvalEvidence(scannerValue: unknown, findingsValue: unknown): AstraOvalEvidenceStatus {
  const reject = (reason: string): AstraOvalEvidenceStatus => ({ complete: false, reason, definitionCount: null });
  const scanner = record(scannerValue);
  if (!scanner || scanner.available !== true || scanner.evaluationPerformed !== true
      || scanner.partial !== false || (scanner.exitCode !== 0 && scanner.exitCode !== 2)
      || !Array.isArray(scanner.partialReasons) || scanner.partialReasons.length !== 0) {
    return reject("scanner_not_fully_completed");
  }
  const source = record(scanner.database);
  if (!source || typeof source.sha256 !== "string" || !SHA.test(source.sha256)
      || source.checksumVerified !== true) return reject("source_sha_not_verified");
  if (typeof scanner.resultSha256 !== "string" || !SHA.test(scanner.resultSha256)) {
    return reject("original_result_sha_missing");
  }
  const count = scanner.definitionCount;
  if (typeof count !== "number" || !Number.isSafeInteger(count) || count <= 0 || count > MAX_DEFINITIONS
      || scanner.evaluatedDefinitionCount !== count || !Array.isArray(scanner.definitionResults)
      || scanner.definitionResults.length !== count) return reject("definition_scope_incomplete");

  const seen = new Set<string>();
  const counts = new Map<string, number>();
  const trueVulnerabilities = new Set<string>();
  for (const value of scanner.definitionResults) {
    const item = record(value);
    if (!item || typeof item.id !== "string" || !OVAL_ID.test(item.id) || seen.has(item.id)) {
      return reject("definition_id_invalid_or_duplicated");
    }
    if (typeof item.result !== "string" || !COMPLETED_STATES.has(item.result)) {
      return reject("definition_state_unresolved");
    }
    seen.add(item.id);
    counts.set(item.result, (counts.get(item.result) ?? 0) + 1);
    if (item.result === "true" && item.class === "vulnerability") trueVulnerabilities.add(item.id);
    else if (item.result === "true" && typeof item.class !== "string") {
      return reject("true_definition_class_unknown");
    }
  }
  const claimed = record(scanner.resultCounts);
  if (!claimed || Object.keys(claimed).length !== counts.size) return reject("definition_count_summary_mismatch");
  for (const [state, size] of counts) if (claimed[state] !== size) return reject("definition_count_summary_mismatch");

  // A true vulnerability cannot silently disappear from normalized findings.
  // The producer emits a finding for positive local and foreign/manual
  // vulnerability definitions; inventory definitions are never CVEs.
  if (!Array.isArray(findingsValue)) return reject("findings_missing");
  const positiveFindings = new Set<string>();
  for (const findingValue of findingsValue) {
    const finding = record(findingValue);
    if (finding && typeof finding.id === "string" && (finding.status === "failed" || finding.status === "manual")) {
      positiveFindings.add(finding.id);
    }
  }
  for (const id of trueVulnerabilities) if (!positiveFindings.has(id)) return reject("positive_vulnerability_finding_missing");
  return { complete: true, reason: "exact_scoped_definition_states_present", definitionCount: count };
}
