import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, openSync } from "node:fs";
import path from "node:path";
import { readNativeReportFile } from "@/lib/native-report-storage";

export type OvalCvss3 = { version: "3.0" | "3.1"; score: number; vector: string };
const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const cache = new Map<string, { signature: string; values: Record<string, OvalCvss3> }>();

export function parseOvalCvss3(value: unknown): OvalCvss3 | null {
  const v = record(value);
  const metrics: Record<string, string> = { AV: "NALP", AC: "LH", PR: "NLH", UI: "NR", S: "UC", C: "NLH", I: "NLH", A: "NLH" };
  if ((v.version !== "3.0" && v.version !== "3.1") || typeof v.score !== "number" || !Number.isFinite(v.score) || v.score <= 0 || v.score > 10 || !Number.isInteger(v.score * 10)
    || typeof v.vector !== "string" || v.vector.length > 200) return null;
  const parts = v.vector.split("/").map(part => part.split(":"));
  if (parts.length !== 8 || new Set(parts.map(([key]) => key)).size !== 8 || parts.some(([key, val, extra]) => extra !== undefined || !Object.hasOwn(metrics, key) || val?.length !== 1 || !metrics[key].includes(val))) return null;
  return { version: v.version as OvalCvss3["version"], score: v.score, vector: v.vector };
}

/** Recover omitted CVSS from an immutable, digest-bound original; never rewrite evidence. */
export function readOvalCvssMetadata(raw: unknown, reportPath: string): Record<string, OvalCvss3> {
  const report = record(raw), scanner = record(report.scanner), evidence = record(report.rawEvidence);
  const id = path.basename(reportPath, ".json");
  if (report.mode !== "astra-oval" || !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,219}$/.test(id) || evidence.version !== 1 || !Array.isArray(evidence.artifacts)) return {};
  const sources = evidence.artifacts.map(record).filter(item => item.kind === "source");
  const source = sources[0];
  if (sources.length !== 1 || source.path !== `.raw-evidence/${id}/source.xml` || typeof source.bytes !== "number" || !Number.isSafeInteger(source.bytes) || source.bytes <= 0 || source.bytes > 192 * 1024 * 1024
    || typeof source.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(source.sha256) || record(scanner.database).sha256 !== source.sha256) return {};
  const handles: number[] = [];
  try {
    for (const part of [path.dirname(reportPath), ".raw-evidence", id]) {
      const previous = handles.at(-1);
      handles.push(openSync(previous === undefined ? part : `/proc/self/fd/${previous}/${part}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    }
    const selected = `/proc/self/fd/${handles.at(-1)}/source.xml`;
    const fd = openSync(selected, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    handles.push(fd);
    const info = fstatSync(fd, { bigint: true });
    if (!info.isFile() || info.nlink !== BigInt(1) || info.size !== BigInt(source.bytes)) return {};
    const signature = [source.sha256, info.dev, info.ino, info.size, info.mtimeNs, info.ctimeNs].join(":");
    const saved = cache.get(reportPath);
    if (saved?.signature === signature) return saved.values;
    const bytes = readNativeReportFile(selected, 192 * 1024 * 1024, { bytes: source.bytes, sha256: source.sha256 });
    const parsed = spawnSync("/usr/bin/python3", [path.resolve(process.cwd(), "../ansible/scripts/hcp-oval-audit.py"), "cvss-metadata"], {
      input: bytes, encoding: "utf8", timeout: 15_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    });
    if (parsed.error || parsed.status !== 0) return {};
    const values: Record<string, OvalCvss3> = {};
    for (const [key, value] of Object.entries(record(JSON.parse(parsed.stdout)))) {
      const cvss = parseOvalCvss3(value);
      if (cvss && /^oval:[a-zA-Z0-9_.:-]{3,200}$/.test(key)) values[key] = cvss;
    }
    if (cache.size >= 4) cache.delete(cache.keys().next().value!);
    cache.set(reportPath, { signature, values });
    return values;
  } catch { return {}; }
  finally { handles.reverse().forEach(fd => closeSync(fd)); }
}
