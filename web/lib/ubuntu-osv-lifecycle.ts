/**
 * Temporal sanity and local-import policy for Canonical OSV observations.
 *
 * A recently imported, pinned historic revision is NOT proof of current
 * publisher data. Publisher freshness verification always remains false here.
 * No network calls, filesystem reads, downloads or remediation.
 */
export type UbuntuOsvLifecycle = {
  schemaVersion: 1;
  state: "import_window_ok" | "stale_import" | "withdrawn_record"
    | "invalid_timestamps" | "future_timestamps" | "unpinned_origin";
  reason: string;
  assessedAt: string;
  importedAt: string | null;
  importAgeHours: number | null;
  maxImportAgeHours: number;
  publishedAt: string | null;
  modifiedAt: string | null;
  withdrawnAt: string | null;
  revision: string | null;
  candidateAllowed: boolean;
  publisherFreshnessVerified: false;
  publisherAuthenticated: false;
};

const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const REVISION = /^[a-f0-9]{40}$/;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

function utcTime(raw: unknown): { valid: boolean; ms: number | null; iso: string | null } {
  if (typeof raw !== "string" || !RFC3339_UTC.test(raw)) return { valid: false, ms: null, iso: null };
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? { valid: true, ms, iso: raw } : { valid: false, ms: null, iso: null };
}

export function evaluateUbuntuOsvLifecycle(input: {
  importedAt: unknown;
  record: Record<string, unknown>;
  revision: unknown;
  now?: string;
  maxImportAgeHours?: number;
}): UbuntuOsvLifecycle {
  const maxImportAgeHours = input.maxImportAgeHours ?? 168;
  if (!Number.isInteger(maxImportAgeHours) || maxImportAgeHours < 1 || maxImportAgeHours > 8760) {
    throw new Error("Invalid Ubuntu OSV import-age policy");
  }
  const now = utcTime(input.now ?? new Date().toISOString());
  if (!now.valid || now.ms === null) throw new Error("Invalid UTC assessment timestamp");

  const imported = utcTime(input.importedAt);
  const modified = utcTime(input.record.modified);
  const published = input.record.published === undefined ? null : utcTime(input.record.published);
  const withdrawn = input.record.withdrawn === undefined ? null : utcTime(input.record.withdrawn);
  const revision = typeof input.revision === "string" && REVISION.test(input.revision) ? input.revision : null;
  const importAgeHours = imported.ms === null ? null : Math.max(0, (now.ms - imported.ms) / 3_600_000);

  const base: UbuntuOsvLifecycle = {
    schemaVersion: 1, state: "invalid_timestamps", reason: "invalid_or_missing_temporal_evidence",
    assessedAt: now.iso!, importedAt: imported.iso, importAgeHours,
    maxImportAgeHours, publishedAt: published?.iso ?? null, modifiedAt: modified.iso,
    withdrawnAt: withdrawn?.iso ?? null, revision,
    candidateAllowed: false, publisherFreshnessVerified: false, publisherAuthenticated: false,
  };
  if (!revision) return { ...base, state: "unpinned_origin", reason: "canonical_revision_not_pinned" };
  if (!imported.valid || !modified.valid || published?.valid === false || withdrawn?.valid === false
    || (published?.ms !== null && published?.ms !== undefined && modified.ms !== null && published.ms > modified.ms)) {
    return base;
  }
  if (imported.ms! > now.ms + MAX_FUTURE_SKEW_MS || modified.ms! > now.ms + MAX_FUTURE_SKEW_MS
    || (published?.ms !== null && published?.ms !== undefined && published.ms > now.ms + MAX_FUTURE_SKEW_MS)
    || (withdrawn?.ms !== null && withdrawn?.ms !== undefined && withdrawn.ms > now.ms + MAX_FUTURE_SKEW_MS)) {
    return { ...base, state: "future_timestamps", reason: "future_dated_advisory_or_import" };
  }
  // Even a future-effective withdrawal must be reviewed rather than ignored.
  if (withdrawn) return { ...base, state: "withdrawn_record", reason: "ubuntu_osv_withdrawn" };
  if (importAgeHours === null || importAgeHours > maxImportAgeHours) {
    return { ...base, state: "stale_import", reason: "local_snapshot_import_window_expired" };
  }
  return { ...base, state: "import_window_ok", reason: "local_import_age_acceptable_upstream_currency_unverified",
    candidateAllowed: true };
}
