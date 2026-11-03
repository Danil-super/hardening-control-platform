import {
  getDebianTrackerLastImportedSha256, getDebianTrackerSelection,
  getHcpStateDirectory, getVulnerabilityDatabaseSettings,
  recordDebianTrackerImportedSnapshot, selectDebianTrackerSnapshot,
} from "@/lib/state-store";
import {
  DEBIAN_TRACKER_URL, importDebianTrackerFullSnapshot, readDebianTrackerSnapshotManifest,
  readPinnedDebianTrackerFullSnapshot, type DebianTrackerFullManifest,
} from "@/lib/debian-tracker-snapshot";

const SHA = /^[a-f0-9]{64}$/;
let importInProgress = false;

export class DebianTrackerManagementError extends Error {
  constructor(readonly code: "busy" | "invalid" | "not_imported" | "stale" | "integrity" | "conflict" | "offline", message: string) {
    super(message);
    this.name = "DebianTrackerManagementError";
  }
}

function statusManifest(sha256: string | null): DebianTrackerFullManifest | null {
  if (!sha256 || !SHA.test(sha256)) return null;
  try { return readDebianTrackerSnapshotManifest(getHcpStateDirectory(), sha256); }
  catch { return null; }
}

/** Never read or transmit the full 88+ MiB advisory in a GET response. */
export function getDebianTrackerManagementStatus() {
  const selected = getDebianTrackerSelection();
  const last = getDebianTrackerLastImportedSha256();
  const newest = statusManifest(last);
  const active = selected.sha256 === last ? newest : statusManifest(selected.sha256);
  return {
    ok: true,
    sourceUrl: DEBIAN_TRACKER_URL,
    selectedSha256: selected.sha256,
    selectionSource: selected.source,
    selectionUpdatedAt: selected.updatedAt,
    selectedManifest: active,
    lastImportedSha256: last,
    lastImportedManifest: newest,
    localSelectionAvailable: selected.sha256 ? Boolean(active) : false,
    importInProgress,
    publisherAuthenticated: false as const,
    publisherFreshnessVerified: false as const,
    remediationAuthorized: false as const,
    note: "Совпадение SHA-256 и успешное HTTPS-соединение не доказывают цифровую подпись Debian, текущую полноту CVE или происхождение пакета.",
  };
}

/**
 * Explicit administrator action only. Fixed official endpoint and bounded
 * decoder are enforced by the importer; no arbitrary URLs, host commands
 * or background refresh. An identical re-download retains original captureAt.
 */
export async function fetchDebianTrackerCandidate(input: {
  expectedSha256?: string;
  fetchImpl?: typeof fetch;
  now?: string;
} = {}) {
  if (importInProgress) throw new DebianTrackerManagementError("busy", "Уже выполняется загрузка Debian Security Tracker.");
  if (getVulnerabilityDatabaseSettings().mode === "offline") {
    throw new DebianTrackerManagementError("offline", "Включён локальный режим CVE-баз. Для сетевой загрузки переключите Trivy в сетевой режим.");
  }
  if (input.expectedSha256 !== undefined && !SHA.test(input.expectedSha256)) {
    throw new DebianTrackerManagementError("invalid", "Некорректная независимая контрольная сумма.");
  }
  importInProgress = true;
  try {
    const manifest = await importDebianTrackerFullSnapshot({
      stateRoot: getHcpStateDirectory(), expectedSha256: input.expectedSha256,
      fetchImpl: input.fetchImpl, now: input.now, reuseIdenticalSnapshot: true,
    });
    const earlier = getDebianTrackerLastImportedSha256();
    recordDebianTrackerImportedSnapshot(manifest.sha256, earlier === manifest.sha256);
    // A new download NEVER changes the active per-scan source. Administrator
    // must separately review and approve it through a second PATCH.
    return { ...getDebianTrackerManagementStatus(), imported: manifest };
  } finally {
    importInProgress = false;
  }
}

/** Approval checks complete immutable bytes and only the most recently imported digest. */
export function approveDebianTrackerSelection(input: {
  selectedSha256: string | null;
  expectedSha256: string | null;
  now?: string;
  maxImportAgeHours?: number;
}) {
  const selected = input.selectedSha256;
  if (selected !== null && !SHA.test(selected)
    || input.expectedSha256 !== null && !SHA.test(input.expectedSha256)) {
    throw new DebianTrackerManagementError("invalid", "Некорректная контрольная сумма Debian.");
  }
  if (selected !== null) {
    if (selected !== getDebianTrackerLastImportedSha256()) {
      throw new DebianTrackerManagementError("not_imported", "Можно выбрать только последний импортированный и проверенный снимок.");
    }
    let manifest: DebianTrackerFullManifest;
    try {
      manifest = readPinnedDebianTrackerFullSnapshot(getHcpStateDirectory(), selected).manifest;
    } catch {
      throw new DebianTrackerManagementError("integrity", "Не удалось подтвердить целостность полной базы Debian. Выбор не изменён.");
    }
    const maxAge = input.maxImportAgeHours ?? Number(process.env.HCP_DEBIAN_TRACKER_MAX_IMPORT_AGE_HOURS ?? "168");
    const nowMs = Date.parse(input.now ?? new Date().toISOString());
    const age = (nowMs - Date.parse(manifest.capturedAt)) / 3_600_000;
    if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > 8760 || !Number.isFinite(age)) {
      throw new DebianTrackerManagementError("invalid", "Некорректная политика возраста снимка.");
    }
    if (age > maxAge || age < -5 / 60) {
      throw new DebianTrackerManagementError("stale", "Локальный снимок Debian устарел или имеет недостоверную дату. Загрузите новую версию.");
    }
  }
  try { selectDebianTrackerSnapshot(selected, input.expectedSha256); }
  catch (error) {
    if (error instanceof Error && /selection changed/.test(error.message)) {
      throw new DebianTrackerManagementError("conflict", "Источник изменился в другом сеансе. Обновите страницу.");
    }
    throw error;
  }
  return getDebianTrackerManagementStatus();
}
