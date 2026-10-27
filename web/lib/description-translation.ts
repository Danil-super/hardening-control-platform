import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import { needsRussianTranslation } from "@/lib/finding-language";
export { needsRussianTranslation } from "@/lib/finding-language";

export type DescriptionTranslation = { text: string; language: "ru"; machineTranslated: boolean; engine: string };
const engine = "argos-en-ru-1.9-glossary-v4";
const pending = new Map<string, Promise<DescriptionTranslation>>();
// Only expanded rows are translated. Bound CPU and memory across all sessions.
let running = 0;
const waiting: Array<() => void> = [];

export function verifyTranslation(original: string, translated: string) {
  const identifiers = (text: string) => (text.match(/\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|\d+(?:\.\d+){1,}(?:[a-zA-Z][a-zA-Z0-9]*)?)\b/g) ?? []).sort().join("\n");
  return translated.length > 0 && translated.length <= 40_000 && /[А-Яа-яЁё]/.test(translated) && identifiers(original) === identifiers(translated);
}

function cachePath(key: string) {
  const directory = path.join(process.env.HCP_STATE_DIR ?? path.resolve(process.cwd(), "..", "ansible"), "description-translations");
  if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Хранилище переводов недоступно.");
  chmodSync(directory, 0o700);
  return path.join(directory, `${key}.json`);
}

async function runTranslator(text: string): Promise<DescriptionTranslation> {
  if (running >= 2) {
    if (waiting.length >= 24) throw new Error("Переводчик занят. Повторите запрос немного позже.");
    await new Promise<void>((resolve, reject) => {
      const proceed = () => { clearTimeout(timer); resolve(); };
      const timer = setTimeout(() => {
        const index = waiting.indexOf(proceed);
        if (index >= 0) waiting.splice(index, 1);
        reject(new Error("Переводчик занят. Повторите запрос немного позже."));
      }, 50_000);
      waiting.push(proceed);
    });
  } else running += 1;
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn("/opt/hcp-tools/translation/bin/python", [path.resolve(process.cwd(), "..", "ansible", "scripts", "hcp-description-translate.py")], { stdio: ["pipe", "pipe", "pipe"] });
      const chunks: Buffer[] = [];
      let size = 0;
      let stopped = false;
      const timer = setTimeout(() => { stopped = true; child.kill("SIGKILL"); }, 60_000);
      child.stdout.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 160_000) { stopped = true; child.kill("SIGKILL"); } else chunks.push(chunk); });
      child.stderr.on("data", () => {});
      child.stdin.on("error", () => {});
      child.on("error", () => { clearTimeout(timer); reject(new Error("Локальный переводчик недоступен. Оригинал описания сохранён.")); });
      child.on("close", (code) => {
        clearTimeout(timer);
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (stopped || code !== 0 || result.engine !== engine || typeof result.text !== "string" || !verifyTranslation(text, result.text)) throw new Error();
          resolve({ text: result.text, language: "ru", machineTranslated: true, engine });
        } catch { reject(new Error("Не удалось получить проверенный перевод. Английский оригинал доступен ниже.")); }
      });
      child.stdin.end(JSON.stringify({ text }));
    });
  } finally {
    const next = waiting.shift();
    if (next) next(); else running -= 1;
  }
}

export async function translateDescription(text: string): Promise<DescriptionTranslation> {
  if (!text.trim() || text.length > 20_000) throw new Error("Описание слишком велико для автоматического перевода.");
  if (!needsRussianTranslation(text)) return { text, language: "ru", machineTranslated: false, engine: "original" };
  const key = createHash("sha256").update(engine + "\n" + text).digest("hex");
  const pathname = cachePath(key);
  const info = lstatSync(pathname, { throwIfNoEntry: false });
  if (info && (!info.isFile() || info.isSymbolicLink())) throw new Error("Запись перевода имеет недопустимый тип.");
  if (info && info.size <= 160_000) {
    try {
      const cached = JSON.parse(readFileSync(pathname, "utf8"));
      if (cached.engine === engine && cached.sourceSha256 === createHash("sha256").update(text).digest("hex") && typeof cached.text === "string" && verifyTranslation(text, cached.text)) {
        return { text: cached.text, language: "ru", machineTranslated: true, engine };
      }
    } catch { /* Regenerate malformed or obsolete cache entries. */ }
  }
  const existing = pending.get(key);
  if (existing) return existing;
  const request = (async () => {
    const result = await runTranslator(text);
    const temporary = `${pathname}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temporary, JSON.stringify({ ...result, sourceSha256: createHash("sha256").update(text).digest("hex") }), { mode: 0o600, flag: "wx" });
      renameSync(temporary, pathname);
    } finally { if (existsSync(temporary)) rmSync(temporary); }
    return result;
  })();
  pending.set(key, request);
  try { return await request; } finally { pending.delete(key); }
}
