export type NmapScanScope = "top_100" | "top_1000" | "full_tcp";

const scopes = {
  top_100: { coverage: "top_100_tcp", label: "100 наиболее распространённых TCP-портов; UDP не проверялся" },
  top_1000: { coverage: "top_1000_tcp", label: "1000 наиболее распространённых TCP-портов; UDP не проверялся" },
  full_tcp: { coverage: "all_tcp_1_65535", label: "Все TCP-порты 1–65535; UDP не проверялся" },
} as const;

export function normalizeNmapScope(value: unknown): NmapScanScope | null {
  return typeof value === "string" && Object.hasOwn(scopes, value) ? value as NmapScanScope : null;
}

export function nmapPortCoverage(scope: NmapScanScope | null | undefined) {
  return scope ? scopes[scope].coverage : null;
}

export function nmapScopeLabel(scope: NmapScanScope | null | undefined) {
  return scope ? scopes[scope].label : "Область TCP-проверки неизвестна";
}

export function nmapScopeIncludes(current: NmapScanScope | null | undefined, previous: NmapScanScope | null | undefined) {
  // Full TCP has a fixed range. The ranking behind --top-ports can change
  // with nmap-services; no pinned port-set identity is stored in old reports.
  return Boolean(current && previous && (current === "full_tcp" || current === previous));
}
