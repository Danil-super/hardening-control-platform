import { createHmac, randomUUID } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

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
  status: "preparing" | "backed_up" | "applied" | "failed" | "rolled_back";
  reason: string;
  parameters: Record<string, string>;
  backupRef: string | null;
  preAuditReportId: string | null;
  postAuditReportId: string | null;
  error: string | null;
};

function getStateDirectory() {
  const repoRoot = path.resolve(process.cwd(), "..");
  return process.env.HCP_STATE_DIR ? path.resolve(process.env.HCP_STATE_DIR) : path.join(repoRoot, "ansible");
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
  database.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
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
  `);
  globalRef.hcpDatabase = database;
  globalRef.hcpDatabasePath = databasePath;
  return database;
}

function canonicalJson(value: unknown) {
  return JSON.stringify(value, Object.keys(value as Record<string, unknown>).sort());
}

function auditIntegrityKey() {
  return process.env.HCP_AUDIT_HMAC_KEY || process.env.HCP_AUTH_SECRET || process.env.HCP_ADMIN_PASSWORD || "hcp-development-only-key";
}

function computeEntryHash(value: Record<string, unknown>) {
  return createHmac("sha256", auditIntegrityKey()).update(canonicalJson(value)).digest("hex");
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
  const database = getDatabase();
  const createdAt = new Date().toISOString();
  const previous = database.prepare("SELECT entry_hash FROM audit_events ORDER BY created_at DESC, rowid DESC LIMIT 1").get();
  const previousHash = typeof previous?.entry_hash === "string" ? previous.entry_hash : null;
  const payloadJson = JSON.stringify(payload);
  const hash = computeEntryHash({ createdAt, eventType, entityId, payload, previousHash });
  database.prepare(`
    INSERT INTO audit_events (id, created_at, event_type, entity_id, payload_json, previous_hash, entry_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(randomUUID(), createdAt, eventType, entityId, payloadJson, previousHash, hash);
  return { createdAt, entryHash: hash, previousHash };
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
    .prepare("SELECT created_at, event_type, entity_id, payload_json, previous_hash, entry_hash FROM audit_events ORDER BY created_at ASC, rowid ASC")
    .all();
  let previousHash: string | null = null;
  for (const row of rows) {
    const payload = JSON.parse(String(row.payload_json));
    const expectedHash: string = computeEntryHash({
      createdAt: row.created_at,
      eventType: row.event_type,
      entityId: row.entity_id,
      payload,
      previousHash,
    });
    if (row.previous_hash !== previousHash || row.entry_hash !== expectedHash) {
      return { valid: false, entries: rows.length, brokenAt: String(row.entity_id) };
    }
    previousHash = String(row.entry_hash);
  }
  return { valid: true, entries: rows.length, brokenAt: null };
}

export function createRemediationTransaction(input: Omit<RemediationTransaction, "createdAt" | "updatedAt" | "status" | "backupRef" | "preAuditReportId" | "postAuditReportId" | "error">) {
  const now = new Date().toISOString();
  getDatabase().prepare(`
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
}

export function updateRemediationTransaction(
  id: string,
  update: Partial<Pick<RemediationTransaction, "status" | "backupRef" | "preAuditReportId" | "postAuditReportId" | "error">>,
) {
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
