/**
 * Presentation-only parsing of the read-only host policy assignment API.
 * A configured source is NEVER proof of a scan, current OS applicability, feed
 * freshness, publisher signature, supported CVE coverage or remediation authority.
 */
export type SourceAssignmentState = "configured" | "missing" | "conflict" | "incomplete";
export type SourceAssignment = {
  state: SourceAssignmentState;
  group: string | null;
  message: string;
  profileKind?: "astra-hcp-18" | "custom" | "environment" | null;
  declaredRelease?: string | null;
};

export type SourceGuidance = {
  alias: string;
  astraOval: SourceAssignment;
  openScap: SourceAssignment;
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const statuses = new Set(["configured", "missing", "conflict", "incomplete"]);
const profileKinds = new Set(["astra-hcp-18", "custom", "environment"]);

export function parseSourceGuidance(value: unknown, requestedAlias: string): SourceGuidance | null {
  if (!isRecord(value) || value.ok !== true || value.assessment !== "saved-settings-only"
    || value.alias !== requestedAlias) return null;
  const parseAssignment = (v: unknown): SourceAssignment | null => {
    if (!isRecord(v) || !statuses.has(v.state as string) || (v.group !== null
      && !(typeof v.group === "string" && v.group.length > 0 && v.group.length <= 128))
      || typeof v.message !== "string" || !v.message || v.message.length > 1200) return null;
    if (v.profileKind !== undefined && v.profileKind !== null
      && !profileKinds.has(v.profileKind as string)) return null;
    if (v.declaredRelease !== undefined && v.declaredRelease !== null
      && (typeof v.declaredRelease !== "string" || v.declaredRelease.length > 128)) return null;
    return {
      state: v.state as SourceAssignmentState, group: v.group as string | null,
      message: v.message, profileKind: v.profileKind as SourceAssignment["profileKind"],
      declaredRelease: v.declaredRelease as string | null | undefined,
    };
  };
  const astraOval = parseAssignment(value.astraOval);
  const openScap = parseAssignment(value.openScap);
  return astraOval && openScap ? { alias: requestedAlias, astraOval, openScap } : null;
}

export function describeSourceAssignment(source: SourceAssignment) {
  switch (source.state) {
    case "configured": return { label: "Назначено (не проверено)", tone: "neutral" as const };
    case "missing": return { label: "Не назначено", tone: "neutral" as const };
    case "conflict": return { label: "Конфликт групп", tone: "warning" as const };
    case "incomplete": return { label: "Нужна корректировка", tone: "warning" as const };
  }
}
