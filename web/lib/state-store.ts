import { createHmac, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { assertAstraOvalProvenance, validateAstraOvalConfig, type AstraOvalConfig } from "@/lib/astra-oval-config";

type DatabaseGlobal = typeof globalThis & {
  hcpDatabase?: DatabaseSync;
  hcpDatabasePath?: string;
};

export type IncidentRecord = {
  id: string;
  createdAt: string;
  action: string;
  kind: "audit" | "response" | "system";
  status: "success" | "failed";
  profileId: string;
  limit: string | null;
  message: string;
  command?: string;
  runId?: string;
};

export type RemediationTransaction = {
  id: string;
  createdAt: string;
  updatedAt: string;
  hostAlias: string;
  action: string;
  profileId: string;
  status: "preparing" | "backed_up" | "applied" | "failed" | "rolling_back" | "rollback_failed" | "rolled_back";
  reason: string;
  parameters: Record<string, string>;
  backupRef: string | null;
  preAuditReportId: string | null;
  postAuditReportId: string | null;
  error: string | null;
};

export const remediationPlanStatuses = ["discovered", "proposed", "agreed", "completed", "confirmed", "accepted_risk"] as const;
export type RemediationPlanStatus = typeof remediationPlanStatuses[number];

export type PlanEvidence = {
  reportId: string;
  findingId: string;
  source: string;
  mode: string;
  createdAt: string | null;
  evidence: string;
  reportSha256: string;
};

export type RemediationPlanItem = {
  id: string;
  hostAlias: string;
  findingKey: string;
  title: string;
  category: string;
  risk: "high" | "medium" | "low" | "info";
  description: string;
  recommendation: string;
  evidence: PlanEvidence[];
  status: RemediationPlanStatus;
  owner: string | null;
  dueAt: string | null;
  approvalReference: string | null;
  implementationNote: string | null;
  verificationReportId: string | null;
  riskAcceptedUntil: string | null;
  createdAt: string;
  updatedAt: string;
};

export type RemediationPlanHistory = {
  id: string;
  planId: string;
  createdAt: string;
  fromStatus: RemediationPlanStatus | null;
  toStatus: RemediationPlanStatus;
  note: string | null;
  approvalReference: string | null;
  verificationReportId: string | null;
  riskAcceptedUntil: string | null;
};

export type StoredReportReference = {
  kind: "remediation" | "plan_evidence" | "plan_verification";
  id: string;
  hostAlias: string;
};

export type ProjectReportRecord = {
  id: string;
  createdAt: string;
  hostAlias: string;
  fileName: string;
  pdfSha256: string;
  snapshotSha256: string;
  sourceManifestSha256: string;
  subject: { clientName: string; projectName: string; period: string; specialist: string };
};

export type VulnerabilityDatabaseMode = "online" | "offline";

export type VulnerabilityDatabaseSettings = {
  /**
   * online — Trivy may update its vulnerability database through the network.
   * offline — Trivy uses only the cache already present on the control node.
   */
  mode: VulnerabilityDatabaseMode;
  source: "interface" | "environment";
  updatedAt: string | null;
};

export type OpenScapPolicy = {
  groupName: string;
  datastream: string;
  profile: string;
  createdAt: string;
  updatedAt: string;
};

export type AstraOvalPolicy = { groupName: string; config: AstraOvalConfig; updatedAt: string };

export type OpenScapException = {
  id: string;
  groupName: string;
  ruleId: string;
  reason: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};

function getStateDirectory() {
  const repoRoot = path.resolve(process.cwd(), "..");
  return process.env.HCP_STATE_DIR ? path.resolve(process.env.HCP_STATE_DIR) : path.join(repoRoot, "ansible");
}

export function getHcpStateDirectory() {
  return getStateDirectory();
}

function getDatabasePath() {
  return path.join(getStateDirectory(), "hcp.sqlite");
}

function getDatabase() {
  const databasePath = getDatabasePath();
  const globalRef = globalThis as DatabaseGlobal;
  if (globalRef.hcpDatabase && globalRef.hcpDatabasePath === databasePath) {
    return globalRef.hcpDatabase;
  }
  if (globalRef.hcpDatabase) {
    globalRef.hcpDatabase.close();
  }
  const stateDirectory = path.dirname(databasePath);
  if (!existsSync(stateDirectory)) {
    mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
  }
  const database = new DatabaseSync(databasePath);
  chmodSync(databasePath, 0o600);
  database.exec("PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
  database.exec(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      event_type TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      previous_hash TEXT,
      entry_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX IF NOT EXISTS audit_events_created_at ON audit_events(created_at DESC);

    CREATE TABLE IF NOT EXISTS remediation_transactions (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      host_alias TEXT NOT NULL,
      action TEXT NOT NULL,
      profile_id TEXT NOT NULL,
      status TEXT NOT NULL,
      reason TEXT NOT NULL,
      parameters_json TEXT NOT NULL,
      backup_ref TEXT,
      pre_audit_report_id TEXT,
      post_audit_report_id TEXT,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS remediation_transactions_host_created ON remediation_transactions(host_alias, created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS remediation_transactions_active_host
      ON remediation_transactions(host_alias)
      WHERE status IN ('preparing', 'backed_up');
    CREATE UNIQUE INDEX IF NOT EXISTS remediation_transactions_exclusive_host
      ON remediation_transactions(host_alias)
      WHERE status IN ('preparing', 'backed_up', 'rolling_back');

    CREATE TABLE IF NOT EXISTS runtime_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS openscap_policies (
      group_name TEXT PRIMARY KEY,
      datastream TEXT NOT NULL,
      profile TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS astra_oval_policies (
      group_name TEXT PRIMARY KEY,
      config_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS openscap_exceptions (
      id TEXT PRIMARY KEY,
      group_name TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(group_name, rule_id)
    );
    CREATE INDEX IF NOT EXISTS openscap_exceptions_group_expiry
      ON openscap_exceptions(group_name, expires_at);

    CREATE TABLE IF NOT EXISTS remediation_plan_items (
      id TEXT PRIMARY KEY,
      host_alias TEXT NOT NULL,
      finding_key TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      risk TEXT NOT NULL,
      description TEXT NOT NULL,
      recommendation TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      status TEXT NOT NULL,
      owner TEXT,
      due_at TEXT,
      approval_reference TEXT,
      implementation_note TEXT,
      verification_report_id TEXT,
      risk_accepted_until TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS remediation_plan_items_host_updated
      ON remediation_plan_items(host_alias, updated_at DESC);

    CREATE TABLE IF NOT EXISTS remediation_plan_history (
      id TEXT PRIMARY KEY,
      plan_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      from_status TEXT,
      to_status TEXT NOT NULL,
      note TEXT,
      approval_reference TEXT,
      verification_report_id TEXT,
      risk_accepted_until TEXT,
      FOREIGN KEY(plan_id) REFERENCES remediation_plan_items(id)
    );
    CREATE INDEX IF NOT EXISTS remediation_plan_history_plan_created
      ON remediation_plan_history(plan_id, created_at ASC);

    CREATE TABLE IF NOT EXISTS project_reports (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      host_alias TEXT NOT NULL,
      file_name TEXT NOT NULL UNIQUE,
      pdf_sha256 TEXT NOT NULL,
      snapshot_sha256 TEXT NOT NULL,
      source_manifest_sha256 TEXT NOT NULL,
      subject_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS project_reports_host_created
      ON project_reports(host_alias, created_at DESC);
  `);
  // Preserve old signatures: their version is exposed by verification instead
  // of silently re-signing history with the stronger payload encoding.
  const auditColumns = database.prepare("PRAGMA table_info(audit_events)").all();
  if (!auditColumns.some((column) => column.name === "hash_version")) {
    try {
      database.exec("ALTER TABLE audit_events ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1");
    } catch (error) {
      // Another worker may have completed this additive migration meanwhile.
      if (!database.prepare("PRAGMA table_info(audit_events)").all().some((column) => column.name === "hash_version")) throw error;
    }
  }
  globalRef.hcpDatabase = database;
  globalRef.hcpDatabasePath = databasePath;
  return database;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, child]) => [key, canonicalValue(child)]));
  }
  return value;
}

const activeTransactions = new WeakSet<DatabaseSync>();

function inTransaction<T>(operation: (database: DatabaseSync) => T): T {
  const database = getDatabase();
  if (activeTransactions.has(database)) return operation(database);
  database.exec("BEGIN IMMEDIATE");
  activeTransactions.add(database);
  try {
    const result = operation(database);
    database.exec("COMMIT");
    return result;
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  } finally {
    activeTransactions.delete(database);
  }
}

function auditIntegrityKey() {
  return process.env.HCP_AUDIT_HMAC_KEY || process.env.HCP_AUTH_SECRET || process.env.HCP_ADMIN_PASSWORD || "hcp-development-only-key";
}

function modeFromEnvironment(): VulnerabilityDatabaseMode {
  return process.env.HCP_TRIVY_MODE?.trim().toLowerCase() === "offline" ? "offline" : "online";
}

export function getVulnerabilityDatabaseSettings(): VulnerabilityDatabaseSettings {
  const row = getDatabase()
    .prepare("SELECT setting_value, updated_at FROM runtime_settings WHERE setting_key = ?")
    .get("vulnerability_database_mode") as { setting_value?: unknown; updated_at?: unknown } | undefined;

  if (row?.setting_value === "online" || row?.setting_value === "offline") {
    return {
      mode: row.setting_value,
      source: "interface",
      updatedAt: typeof row.updated_at === "string" ? row.updated_at : null,
    };
  }

  return { mode: modeFromEnvironment(), source: "environment", updatedAt: null };
}

export function setVulnerabilityDatabaseMode(mode: VulnerabilityDatabaseMode) {
  if (mode !== "online" && mode !== "offline") throw new Error("Некорректный режим базы уязвимостей.");
  return inTransaction(() => {
  const updatedAt = new Date().toISOString();
  getDatabase().prepare(`
    INSERT INTO runtime_settings (setting_key, setting_value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at
  `).run("vulnerability_database_mode", mode, updatedAt);
  appendAuditEvent("vulnerability_database_mode_changed", "vulnerability_database_mode", { mode });
  return { mode, source: "interface" as const, updatedAt };
  });
}

function isSafePolicyIdentifier(value: string) {
  return /^[A-Za-z0-9_.:-]{1,120}$/.test(value);
}

function assertOpenScapGroupName(value: string) {
  if (!isSafePolicyIdentifier(value)) {
    throw new Error("Имя группы может содержать только буквы, цифры, _, -, . и :.");
  }
}

function assertOpenScapRuleId(value: string) {
  if (!isSafePolicyIdentifier(value)) {
    throw new Error("Идентификатор правила OpenSCAP имеет недопустимый формат.");
  }
}

function assertOpenScapDatastream(value: string) {
  if (!value.startsWith("/") || value.length > 512 || value.includes("\0") || value.split("/").includes("..")) {
    throw new Error("Укажите абсолютный путь к SSG datastream без переходов .. .");
  }
}

function assertOpenScapException(reason: string, expiresAt: string) {
  if (reason.trim().length < 10 || reason.trim().length > 500) {
    throw new Error("Причина исключения должна содержать от 10 до 500 символов.");
  }
  const expiresAtMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error("Дата окончания исключения должна быть в будущем.");
  }
  if (expiresAtMs > Date.now() + 1000 * 60 * 60 * 24 * 366 * 2) {
    throw new Error("Исключение нельзя выдать более чем на два года.");
  }
}

function rowToOpenScapPolicy(row: Record<string, unknown>): OpenScapPolicy {
  return {
    groupName: String(row.group_name),
    datastream: String(row.datastream),
    profile: String(row.profile),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function rowToOpenScapException(row: Record<string, unknown>): OpenScapException {
  return {
    id: String(row.id),
    groupName: String(row.group_name),
    ruleId: String(row.rule_id),
    reason: String(row.reason),
    expiresAt: String(row.expires_at),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

export function listOpenScapPolicies() {
  return getDatabase()
    .prepare("SELECT * FROM openscap_policies ORDER BY group_name COLLATE NOCASE ASC")
    .all()
    .map((row) => rowToOpenScapPolicy(row as Record<string, unknown>));
}

export function listAstraOvalPolicies(): AstraOvalPolicy[] {
  return getDatabase().prepare("SELECT * FROM astra_oval_policies ORDER BY group_name COLLATE NOCASE ASC").all()
    .map((row) => ({ groupName: String(row.group_name), config: validateAstraOvalConfig(JSON.parse(String(row.config_json))), updatedAt: String(row.updated_at) }));
}

export function upsertAstraOvalPolicy(groupName: string, value: unknown) {
  assertOpenScapGroupName(groupName);
  const config = validateAstraOvalConfig(value);
  assertAstraOvalProvenance(config);
  return inTransaction((database) => {
    const updatedAt = new Date().toISOString();
    const fixedConfig = { ...config, sourceReviewedAt: updatedAt };
    database.prepare(`INSERT INTO astra_oval_policies (group_name, config_json, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(group_name) DO UPDATE SET config_json = excluded.config_json, updated_at = excluded.updated_at`)
      .run(groupName, JSON.stringify(fixedConfig), updatedAt);
    appendAuditEvent("astra_oval_policy_upserted", groupName, { groupName, config: fixedConfig });
    return { groupName, config: fixedConfig, updatedAt };
  });
}

export function deleteAstraOvalPolicy(groupName: string) {
  assertOpenScapGroupName(groupName);
  return inTransaction((database) => {
    const result = database.prepare("DELETE FROM astra_oval_policies WHERE group_name = ?").run(groupName);
    if (result.changes) appendAuditEvent("astra_oval_policy_deleted", groupName, { groupName });
    return result.changes > 0;
  });
}

export function upsertOpenScapPolicy(input: Pick<OpenScapPolicy, "groupName" | "datastream" | "profile">) {
  return inTransaction(() => {
  const groupName = input.groupName.trim();
  const datastream = input.datastream.trim();
  const profile = input.profile.trim();
  assertOpenScapGroupName(groupName);
  assertOpenScapDatastream(datastream);
  assertOpenScapRuleId(profile);
  const now = new Date().toISOString();
  getDatabase().prepare(`
    INSERT INTO openscap_policies (group_name, datastream, profile, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(group_name) DO UPDATE SET
      datastream = excluded.datastream,
      profile = excluded.profile,
      updated_at = excluded.updated_at
  `).run(groupName, datastream, profile, now, now);
  appendAuditEvent("openscap_policy_upserted", groupName, { groupName, datastream, profile });
  return listOpenScapPolicies().find((policy) => policy.groupName === groupName) ?? null;
  });
}

export function deleteOpenScapPolicy(groupNameInput: string) {
  return inTransaction(() => {
  const groupName = groupNameInput.trim();
  assertOpenScapGroupName(groupName);
  const result = getDatabase().prepare("DELETE FROM openscap_policies WHERE group_name = ?").run(groupName);
  if (result.changes > 0) {
    appendAuditEvent("openscap_policy_deleted", groupName, { groupName });
  }
  return result.changes > 0;
  });
}

export function listOpenScapExceptions() {
  return getDatabase()
    .prepare("SELECT * FROM openscap_exceptions ORDER BY expires_at ASC, group_name COLLATE NOCASE ASC, rule_id COLLATE NOCASE ASC")
    .all()
    .map((row) => rowToOpenScapException(row as Record<string, unknown>));
}

export function upsertOpenScapException(input: Pick<OpenScapException, "groupName" | "ruleId" | "reason" | "expiresAt">) {
  return inTransaction(() => {
  const groupName = input.groupName.trim();
  const ruleId = input.ruleId.trim();
  const reason = input.reason.trim();
  const expiresAtMs = Date.parse(input.expiresAt);
  if (!Number.isFinite(expiresAtMs)) {
    throw new Error("Укажите корректную дату окончания исключения.");
  }
  const expiresAt = new Date(expiresAtMs).toISOString();
  assertOpenScapGroupName(groupName);
  assertOpenScapRuleId(ruleId);
  assertOpenScapException(reason, expiresAt);
  const current = getDatabase().prepare("SELECT id, created_at FROM openscap_exceptions WHERE group_name = ? AND rule_id = ?").get(groupName, ruleId) as { id?: unknown; created_at?: unknown } | undefined;
  const id = typeof current?.id === "string" ? current.id : `openscap_exception_${randomUUID()}`;
  const createdAt = typeof current?.created_at === "string" ? current.created_at : new Date().toISOString();
  const updatedAt = new Date().toISOString();
  getDatabase().prepare(`
    INSERT INTO openscap_exceptions (id, group_name, rule_id, reason, expires_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(group_name, rule_id) DO UPDATE SET
      reason = excluded.reason,
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at
  `).run(id, groupName, ruleId, reason, expiresAt, createdAt, updatedAt);
  appendAuditEvent("openscap_exception_upserted", id, { groupName, ruleId, reason, expiresAt });
  return listOpenScapExceptions().find((exception) => exception.id === id) ?? null;
  });
}

export function deleteOpenScapException(id: string) {
  return inTransaction(() => {
  if (!/^openscap_exception_[a-f0-9-]{36}$/.test(id)) {
    throw new Error("Идентификатор исключения имеет недопустимый формат.");
  }
  const result = getDatabase().prepare("DELETE FROM openscap_exceptions WHERE id = ?").run(id);
  if (result.changes > 0) {
    appendAuditEvent("openscap_exception_deleted", id, { id });
  }
  return result.changes > 0;
  });
}

function computeEntryHash(value: Record<string, unknown>, version = 2) {
  const encoded = version === 1
    ? JSON.stringify(value, Object.keys(value).sort())
    : JSON.stringify(canonicalValue(value));
  return createHmac("sha256", auditIntegrityKey()).update(encoded).digest("hex");
}

function toIncident(row: Record<string, unknown>): IncidentRecord | null {
  if (row.event_type !== "execution") {
    return null;
  }
  try {
    const payload = JSON.parse(String(row.payload_json)) as Omit<IncidentRecord, "id" | "createdAt">;
    return {
      id: String(row.entity_id),
      createdAt: String(row.created_at),
      ...payload,
    };
  } catch {
    return null;
  }
}

export function appendAuditEvent(eventType: string, entityId: string, payload: Record<string, unknown>) {
  return inTransaction((database) => {
  const createdAt = new Date().toISOString();
  const previous = database.prepare("SELECT entry_hash FROM audit_events ORDER BY rowid DESC LIMIT 1").get();
  const previousHash = typeof previous?.entry_hash === "string" ? previous.entry_hash : null;
  const payloadJson = JSON.stringify(payload);
  const hash = computeEntryHash({ createdAt, eventType, entityId, payload: JSON.parse(payloadJson), previousHash });
  database.prepare(`
    INSERT INTO audit_events (id, created_at, event_type, entity_id, payload_json, previous_hash, entry_hash, hash_version)
    VALUES (?, ?, ?, ?, ?, ?, ?, 2)
  `).run(randomUUID(), createdAt, eventType, entityId, payloadJson, previousHash, hash);
  return { createdAt, entryHash: hash, previousHash };
  });
}

export function appendIncident(record: Omit<IncidentRecord, "id" | "createdAt">) {
  const createdAt = new Date().toISOString();
  const incident: IncidentRecord = {
    id: `incident_${createdAt.replace(/[-:.TZ]/g, "")}_${randomUUID().slice(0, 8)}`,
    createdAt,
    ...record,
  };
  appendAuditEvent("execution", incident.id, {
    action: incident.action,
    kind: incident.kind,
    status: incident.status,
    profileId: incident.profileId,
    limit: incident.limit,
    message: incident.message,
    command: incident.command,
    runId: incident.runId,
  });
  return incident;
}

export function readIncidents(limit = 300) {
  const records = getDatabase()
    .prepare("SELECT created_at, event_type, entity_id, payload_json FROM audit_events WHERE event_type = 'execution' ORDER BY created_at DESC, rowid DESC LIMIT ?")
    .all(limit)
    .map(toIncident)
    .filter((record): record is IncidentRecord => Boolean(record));
  return records;
}

export function verifyAuditChain() {
  const rows = getDatabase()
    .prepare("SELECT created_at, event_type, entity_id, payload_json, previous_hash, entry_hash, hash_version FROM audit_events ORDER BY rowid ASC")
    .all();
  const legacyEntries = rows.filter((row) => row.hash_version === 1).length;
  let previousHash: string | null = null;
  for (const row of rows) {
    let payload: unknown;
    try { payload = JSON.parse(String(row.payload_json)); } catch {
      return { valid: false, entries: rows.length, brokenAt: String(row.entity_id), legacyEntries, payloadProtected: false };
    }
    if (row.hash_version !== 1 && row.hash_version !== 2) {
      return { valid: false, entries: rows.length, brokenAt: String(row.entity_id), legacyEntries, payloadProtected: false };
    }
    const expectedHash: string = computeEntryHash({
      createdAt: row.created_at,
      eventType: row.event_type,
      entityId: row.entity_id,
      payload,
      previousHash,
    }, Number(row.hash_version));
    if (row.previous_hash !== previousHash || row.entry_hash !== expectedHash) {
      return { valid: false, entries: rows.length, brokenAt: String(row.entity_id), legacyEntries, payloadProtected: false };
    }
    previousHash = String(row.entry_hash);
  }
  return { valid: true, entries: rows.length, brokenAt: null, legacyEntries, payloadProtected: legacyEntries === 0 };
}

export function createRemediationTransaction(input: Omit<RemediationTransaction, "createdAt" | "updatedAt" | "status" | "backupRef" | "preAuditReportId" | "postAuditReportId" | "error">) {
  return inTransaction((database) => {
  const now = new Date().toISOString();
  database.prepare(`
    INSERT INTO remediation_transactions (
      id, created_at, updated_at, host_alias, action, profile_id, status, reason, parameters_json,
      backup_ref, pre_audit_report_id, post_audit_report_id, error
    ) VALUES (?, ?, ?, ?, ?, ?, 'preparing', ?, ?, NULL, NULL, NULL, NULL)
  `).run(input.id, now, now, input.hostAlias, input.action, input.profileId, input.reason, JSON.stringify(input.parameters));
  appendAuditEvent("remediation_preparing", input.id, {
    hostAlias: input.hostAlias,
    action: input.action,
    profileId: input.profileId,
    reason: input.reason,
    parameters: input.parameters,
  });
  return getRemediationTransaction(input.id);
  });
}

export function updateRemediationTransaction(
  id: string,
  update: Partial<Pick<RemediationTransaction, "status" | "backupRef" | "preAuditReportId" | "postAuditReportId" | "error">>,
) {
  return inTransaction(() => {
  const current = getRemediationTransaction(id);
  if (!current) {
    return null;
  }
  const next = { ...current, ...update, updatedAt: new Date().toISOString() };
  getDatabase().prepare(`
    UPDATE remediation_transactions
    SET updated_at = ?, status = ?, backup_ref = ?, pre_audit_report_id = ?, post_audit_report_id = ?, error = ?
    WHERE id = ?
  `).run(next.updatedAt, next.status, next.backupRef, next.preAuditReportId, next.postAuditReportId, next.error, id);
  appendAuditEvent(`remediation_${next.status}`, id, {
    hostAlias: next.hostAlias,
    action: next.action,
    profileId: next.profileId,
    backupRef: next.backupRef,
    preAuditReportId: next.preAuditReportId,
    postAuditReportId: next.postAuditReportId,
    error: next.error,
  });
  return next;
  });
}

export function hasActiveRemediationForHost(hostAlias: string) {
  return Boolean(getDatabase().prepare(`SELECT 1 FROM remediation_transactions
    WHERE host_alias = ? AND status IN ('preparing', 'backed_up', 'rolling_back') LIMIT 1`).get(hostAlias));
}

export function claimRemediationRollback(id: string): RemediationTransaction {
  return inTransaction((database) => {
    const current = getRemediationTransaction(id);
    if (!current || !current.backupRef || !["applied", "failed", "rollback_failed"].includes(current.status)) {
      throw Object.assign(new Error("Эта операция недоступна для отката."), { code: "rollback_not_available" });
    }
    if (hasActiveRemediationForHost(current.hostAlias)) {
      throw Object.assign(new Error("На хосте уже выполняется изменение или откат."), { code: "host_operation_active" });
    }
    const newer = database.prepare(`SELECT id FROM remediation_transactions
      WHERE host_alias = ? AND rowid > (SELECT rowid FROM remediation_transactions WHERE id = ?)
        AND backup_ref IS NOT NULL AND status IN ('applied', 'failed', 'rollback_failed', 'rolling_back', 'backed_up') LIMIT 1`)
      .get(current.hostAlias, id);
    if (newer) {
      throw Object.assign(new Error("Сначала откатите более поздние изменения этого хоста."), { code: "newer_remediation_exists" });
    }
    const row = database.prepare(`UPDATE remediation_transactions SET status = 'rolling_back', updated_at = ?, error = NULL
      WHERE id = ? AND status IN ('applied', 'failed', 'rollback_failed') AND backup_ref IS NOT NULL RETURNING *`)
      .get(new Date().toISOString(), id);
    if (!row) throw Object.assign(new Error("Операция уже занята или недоступна для отката."), { code: "rollback_not_available" });
    appendAuditEvent("remediation_rolling_back", id, { hostAlias: current.hostAlias, backupRef: current.backupRef });
    return rowToTransaction(row);
  });
}

function rowToTransaction(row: Record<string, unknown>): RemediationTransaction {
  return {
    id: String(row.id),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    hostAlias: String(row.host_alias),
    action: String(row.action),
    profileId: String(row.profile_id),
    status: row.status as RemediationTransaction["status"],
    reason: String(row.reason),
    parameters: JSON.parse(String(row.parameters_json)) as Record<string, string>,
    backupRef: typeof row.backup_ref === "string" ? row.backup_ref : null,
    preAuditReportId: typeof row.pre_audit_report_id === "string" ? row.pre_audit_report_id : null,
    postAuditReportId: typeof row.post_audit_report_id === "string" ? row.post_audit_report_id : null,
    error: typeof row.error === "string" ? row.error : null,
  };
}

export function getRemediationTransaction(id: string) {
  const row = getDatabase().prepare("SELECT * FROM remediation_transactions WHERE id = ?").get(id);
  return row ? rowToTransaction(row) : null;
}

export function listRemediationTransactions(limit = 50) {
  return getDatabase()
    .prepare("SELECT * FROM remediation_transactions ORDER BY created_at DESC LIMIT ?")
    .all(limit)
    .map(rowToTransaction);
}

/**
 * Raw audit reports can be cleaned up, but not while a saved change or a plan
 * still relies on them. This intentionally checks the persisted state rather
 * than the current report list, so a deleted file can never make a reference
 * disappear from the guard.
 */
export function listStoredReportReferences(reportId: string): StoredReportReference[] {
  if (!/^[A-Za-z0-9_.:-]{1,180}$/.test(reportId)) return [];
  const database = getDatabase();
  const references: StoredReportReference[] = [];
  const transactions = database.prepare(`SELECT id, host_alias FROM remediation_transactions
    WHERE pre_audit_report_id = ? OR post_audit_report_id = ?`).all(reportId, reportId);
  for (const row of transactions) {
    const data = row as Record<string, unknown>;
    references.push({ kind: "remediation", id: String(data.id), hostAlias: String(data.host_alias) });
  }

  const plans = database.prepare("SELECT id, host_alias, evidence_json, verification_report_id FROM remediation_plan_items").all();
  for (const row of plans) {
    const data = row as Record<string, unknown>;
    const id = String(data.id);
    const hostAlias = String(data.host_alias);
    if (data.verification_report_id === reportId) {
      references.push({ kind: "plan_verification", id, hostAlias });
    }
    try {
      const evidence = JSON.parse(String(data.evidence_json));
      if (Array.isArray(evidence) && evidence.some((item) => item && typeof item === "object" && !Array.isArray(item) && (item as Record<string, unknown>).reportId === reportId)) {
        references.push({ kind: "plan_evidence", id, hostAlias });
      }
    } catch {
      // Do not delete evidence while the stored plan itself cannot be checked.
      references.push({ kind: "plan_evidence", id, hostAlias });
    }
  }
  return references;
}

function planText(value: unknown, field: string, minimum = 1, maximum = 1200) {
  if (typeof value !== "string") throw new Error(`Поле «${field}» должно быть текстом.`);
  const result = value.trim();
  if (result.length < minimum || result.length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(result)) {
    throw new Error(`Поле «${field}» должно содержать от ${minimum} до ${maximum} символов.`);
  }
  return result;
}

function planIdentifier(value: unknown, field: string, maximum = 180) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.:-]{1,180}$/.test(value) || value.length > maximum) {
    throw new Error(`Поле «${field}» имеет недопустимый формат.`);
  }
  return value;
}

function nullablePlanText(value: unknown, field: string, minimum = 1, maximum = 1200) {
  if (value === undefined || value === null || value === "") return null;
  return planText(value, field, minimum, maximum);
}

function futurePlanDate(value: unknown, field: string, required = false) {
  if (value === undefined || value === null || value === "") {
    if (required) throw new Error(`Укажите дату для поля «${field}».`);
    return null;
  }
  if (typeof value !== "string") throw new Error(`Укажите корректную дату для поля «${field}».`);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()) throw new Error(`Дата «${field}» должна быть в будущем.`);
  if (timestamp > Date.now() + 1000 * 60 * 60 * 24 * 366 * 5) throw new Error(`Дата «${field}» не может быть далее пяти лет.`);
  return new Date(timestamp).toISOString();
}

function planStatus(value: unknown): RemediationPlanStatus {
  if (typeof value !== "string" || !remediationPlanStatuses.includes(value as RemediationPlanStatus)) {
    throw new Error("Укажите поддерживаемый статус плана устранения.");
  }
  return value as RemediationPlanStatus;
}

function parsePlanEvidence(value: unknown): PlanEvidence[] {
  if (!Array.isArray(value) || !value.length || value.length > 24) throw new Error("Для пункта плана нужны технические доказательства из отчёта.");
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Доказательство плана имеет неверный формат.");
    const data = item as Record<string, unknown>;
    const createdAt = data.createdAt === null ? null : typeof data.createdAt === "string" && Number.isFinite(Date.parse(data.createdAt)) ? data.createdAt : null;
    return {
      reportId: planIdentifier(data.reportId, "ID исходного отчёта"),
      findingId: planIdentifier(data.findingId, "ID находки"),
      source: planText(data.source, "источник", 1, 80),
      mode: planText(data.mode, "тип отчёта", 1, 80),
      createdAt,
      evidence: planText(data.evidence || "Нет дополнительного технического доказательства.", "доказательство", 1, 4000),
      reportSha256: typeof data.reportSha256 === "string" && /^[a-f0-9]{64}$/.test(data.reportSha256) ? data.reportSha256 : (() => { throw new Error("Не зафиксирована контрольная сумма исходного отчёта."); })(),
    };
  });
}

function rowToPlanItem(row: Record<string, unknown>): RemediationPlanItem {
  return {
    id: String(row.id), hostAlias: String(row.host_alias), findingKey: String(row.finding_key), title: String(row.title), category: String(row.category),
    risk: row.risk as RemediationPlanItem["risk"], description: String(row.description), recommendation: String(row.recommendation),
    evidence: parsePlanEvidence(JSON.parse(String(row.evidence_json))), status: planStatus(row.status),
    owner: typeof row.owner === "string" ? row.owner : null, dueAt: typeof row.due_at === "string" ? row.due_at : null,
    approvalReference: typeof row.approval_reference === "string" ? row.approval_reference : null,
    implementationNote: typeof row.implementation_note === "string" ? row.implementation_note : null,
    verificationReportId: typeof row.verification_report_id === "string" ? row.verification_report_id : null,
    riskAcceptedUntil: typeof row.risk_accepted_until === "string" ? row.risk_accepted_until : null,
    createdAt: String(row.created_at), updatedAt: String(row.updated_at),
  };
}

function rowToPlanHistory(row: Record<string, unknown>): RemediationPlanHistory {
  return {
    id: String(row.id), planId: String(row.plan_id), createdAt: String(row.created_at),
    fromStatus: row.from_status === null ? null : planStatus(row.from_status), toStatus: planStatus(row.to_status),
    note: typeof row.note === "string" ? row.note : null, approvalReference: typeof row.approval_reference === "string" ? row.approval_reference : null,
    verificationReportId: typeof row.verification_report_id === "string" ? row.verification_report_id : null,
    riskAcceptedUntil: typeof row.risk_accepted_until === "string" ? row.risk_accepted_until : null,
  };
}

function addPlanHistory(database: DatabaseSync, input: Omit<RemediationPlanHistory, "id" | "createdAt">) {
  const id = `plan_history_${randomUUID()}`;
  const createdAt = new Date().toISOString();
  database.prepare(`INSERT INTO remediation_plan_history
    (id, plan_id, created_at, from_status, to_status, note, approval_reference, verification_report_id, risk_accepted_until)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, input.planId, createdAt, input.fromStatus, input.toStatus, input.note, input.approvalReference, input.verificationReportId, input.riskAcceptedUntil);
  return { id, createdAt };
}

export function listRemediationPlanItems(hostAlias?: string) {
  const rows = hostAlias
    ? getDatabase().prepare("SELECT * FROM remediation_plan_items WHERE host_alias = ? ORDER BY updated_at DESC").all(hostAlias)
    : getDatabase().prepare("SELECT * FROM remediation_plan_items ORDER BY updated_at DESC").all();
  return rows.map((row) => rowToPlanItem(row as Record<string, unknown>));
}

export function getRemediationPlanItem(id: string) {
  if (!/^plan_[a-f0-9-]{36}$/.test(id)) return null;
  const row = getDatabase().prepare("SELECT * FROM remediation_plan_items WHERE id = ?").get(id);
  return row ? rowToPlanItem(row as Record<string, unknown>) : null;
}

export function listRemediationPlanHistory(planId: string) {
  if (!/^plan_[a-f0-9-]{36}$/.test(planId)) return [];
  return getDatabase().prepare("SELECT * FROM remediation_plan_history WHERE plan_id = ? ORDER BY created_at ASC").all(planId)
    .map((row) => rowToPlanHistory(row as Record<string, unknown>));
}

export function createRemediationPlanItem(input: Omit<RemediationPlanItem, "id" | "status" | "owner" | "dueAt" | "approvalReference" | "implementationNote" | "verificationReportId" | "riskAcceptedUntil" | "createdAt" | "updatedAt">) {
  const hostAlias = planIdentifier(input.hostAlias, "хост", 96);
  const findingKey = planIdentifier(input.findingKey, "ключ находки", 180);
  const title = planText(input.title, "название", 1, 300);
  const category = planText(input.category, "категория", 1, 120);
  if (!["high", "medium", "low", "info"].includes(input.risk)) throw new Error("Укажите корректный уровень риска.");
  const description = planText(input.description, "описание", 1, 3000);
  const recommendation = planText(input.recommendation, "рекомендация", 1, 3000);
  const evidence = parsePlanEvidence(input.evidence);
  return inTransaction((database) => {
    const existing = database.prepare(`SELECT * FROM remediation_plan_items WHERE host_alias = ? AND finding_key = ?
      AND status NOT IN ('confirmed', 'accepted_risk') ORDER BY updated_at DESC LIMIT 1`).get(hostAlias, findingKey);
    if (existing) return rowToPlanItem(existing as Record<string, unknown>);
    const id = `plan_${randomUUID()}`;
    const now = new Date().toISOString();
    database.prepare(`INSERT INTO remediation_plan_items
      (id, host_alias, finding_key, title, category, risk, description, recommendation, evidence_json, status, owner, due_at,
       approval_reference, implementation_note, verification_report_id, risk_accepted_until, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'discovered', NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)`)
      .run(id, hostAlias, findingKey, title, category, input.risk, description, recommendation, JSON.stringify(evidence), now, now);
    addPlanHistory(database, { planId: id, fromStatus: null, toStatus: "discovered", note: "Пункт создан из свежих доказательств аудита.", approvalReference: null, verificationReportId: null, riskAcceptedUntil: null });
    appendAuditEvent("remediation_plan_created", id, { hostAlias, findingKey, title, risk: input.risk, evidence: evidence.map(({ reportId, findingId, reportSha256 }) => ({ reportId, findingId, reportSha256 })) });
    return getRemediationPlanItem(id);
  });
}

const planTransitions: Record<RemediationPlanStatus, RemediationPlanStatus[]> = {
  discovered: ["proposed"], proposed: ["agreed", "accepted_risk"], agreed: ["proposed", "completed", "accepted_risk"],
  completed: ["agreed", "confirmed"], confirmed: [], accepted_risk: ["proposed"],
};

export function transitionRemediationPlanItem(id: string, update: {
  status: RemediationPlanStatus; note?: unknown; owner?: unknown; dueAt?: unknown; approvalReference?: unknown;
  verificationReportId?: unknown; riskAcceptedUntil?: unknown;
}) {
  return inTransaction((database) => {
    const current = getRemediationPlanItem(id);
    if (!current) throw new Error("Пункт плана устранения не найден.");
    const status = planStatus(update.status);
    if (!planTransitions[current.status].includes(status)) throw new Error("Этот переход статуса плана не разрешён.");
    const note = nullablePlanText(update.note, "комментарий", 10, 2000);
    const owner = nullablePlanText(update.owner, "ответственный", 2, 160) ?? current.owner;
    const dueAt = update.dueAt === undefined ? current.dueAt : futurePlanDate(update.dueAt, "срок");
    const approvalReference = update.approvalReference === undefined ? current.approvalReference : nullablePlanText(update.approvalReference, "ссылка на согласование", 3, 500);
    const verificationReportId = update.verificationReportId === undefined ? current.verificationReportId : (update.verificationReportId ? planIdentifier(update.verificationReportId, "ID повторного отчёта") : null);
    const riskAcceptedUntil = update.riskAcceptedUntil === undefined ? current.riskAcceptedUntil : futurePlanDate(update.riskAcceptedUntil, "срок принятого риска");
    if (status === "proposed" && !note) throw new Error("Опишите предлагаемую меру и её возможный риск.");
    if (status === "agreed" && (!note || !owner || !dueAt || !approvalReference)) throw new Error("Для согласования укажите комментарий, ответственного, срок и ссылку на внешний документ или тикет.");
    if (status === "completed" && !note) throw new Error("Опишите фактически выполненную меру.");
    if (status === "confirmed" && (!note || !verificationReportId)) throw new Error("Для подтверждения укажите результат повторного аудита и комментарий.");
    if (status === "accepted_risk" && (!note || !owner || !approvalReference || !riskAcceptedUntil)) throw new Error("Для принятия риска укажите причину, согласовавшего, ссылку на документ и срок действия.");
    const updatedAt = new Date().toISOString();
    database.prepare(`UPDATE remediation_plan_items SET status = ?, owner = ?, due_at = ?, approval_reference = ?,
      implementation_note = ?, verification_report_id = ?, risk_accepted_until = ?, updated_at = ? WHERE id = ?`)
      .run(status, owner, dueAt, approvalReference, status === "completed" ? note : current.implementationNote,
        verificationReportId, riskAcceptedUntil, updatedAt, id);
    addPlanHistory(database, { planId: id, fromStatus: current.status, toStatus: status, note, approvalReference, verificationReportId, riskAcceptedUntil });
    appendAuditEvent("remediation_plan_transition", id, { hostAlias: current.hostAlias, findingKey: current.findingKey, fromStatus: current.status, toStatus: status, note, owner, dueAt, approvalReference, verificationReportId, riskAcceptedUntil });
    return getRemediationPlanItem(id);
  });
}

function rowToProjectReport(row: Record<string, unknown>): ProjectReportRecord {
  const subject = JSON.parse(String(row.subject_json)) as ProjectReportRecord["subject"];
  return { id: String(row.id), createdAt: String(row.created_at), hostAlias: String(row.host_alias), fileName: String(row.file_name),
    pdfSha256: String(row.pdf_sha256), snapshotSha256: String(row.snapshot_sha256), sourceManifestSha256: String(row.source_manifest_sha256), subject };
}

export function createProjectReportRecord(input: ProjectReportRecord) {
  if (!/^project_report_[a-f0-9-]{36}$/.test(input.id)) throw new Error("Некорректный ID итогового отчёта.");
  const hostAlias = planIdentifier(input.hostAlias, "хост", 96);
  if (!/^project-report-[a-f0-9-]{36}\.pdf$/.test(input.fileName)) throw new Error("Некорректное имя итогового отчёта.");
  for (const value of [input.pdfSha256, input.snapshotSha256, input.sourceManifestSha256]) if (!/^[a-f0-9]{64}$/.test(value)) throw new Error("Не зафиксирована контрольная сумма итогового отчёта.");
  const subject = {
    clientName: planText(input.subject.clientName, "заказчик", 2, 200), projectName: planText(input.subject.projectName, "проект", 2, 200),
    period: planText(input.subject.period, "период", 2, 120), specialist: planText(input.subject.specialist, "специалист", 2, 200),
  };
  return inTransaction((database) => {
    database.prepare(`INSERT INTO project_reports (id, created_at, host_alias, file_name, pdf_sha256, snapshot_sha256, source_manifest_sha256, subject_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(input.id, input.createdAt, hostAlias, input.fileName, input.pdfSha256, input.snapshotSha256, input.sourceManifestSha256, JSON.stringify(subject));
    appendAuditEvent("project_report_exported", input.id, { hostAlias, fileName: input.fileName, pdfSha256: input.pdfSha256, snapshotSha256: input.snapshotSha256, sourceManifestSha256: input.sourceManifestSha256 });
    return getProjectReportRecord(input.id);
  });
}

export function getProjectReportRecord(id: string) {
  if (!/^project_report_[a-f0-9-]{36}$/.test(id)) return null;
  const row = getDatabase().prepare("SELECT * FROM project_reports WHERE id = ?").get(id);
  return row ? rowToProjectReport(row as Record<string, unknown>) : null;
}

export function listProjectReportRecords(hostAlias?: string) {
  const rows = hostAlias ? getDatabase().prepare("SELECT * FROM project_reports WHERE host_alias = ? ORDER BY created_at DESC").all(hostAlias)
    : getDatabase().prepare("SELECT * FROM project_reports ORDER BY created_at DESC").all();
  return rows.map((row) => rowToProjectReport(row as Record<string, unknown>));
}
