"use client";

import { useEffect, useState } from "react";
import { Database, RefreshCw, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { readApiResponse, errorMessage } from "@/lib/client-api";

type Manifest = {
  sha256: string;
  bytes: number;
  capturedAt: string;
  sourcePackageCount: number;
  issueCount: number;
  pinMode: "observed-at-capture" | "independently-specified-sha256";
};
type Status = {
  ok: boolean;
  sourceUrl: string;
  mode: "online" | "offline";
  maxImportAgeHours: number;
  selectedSha256: string | null;
  selectionSource: "environment" | "interface";
  selectionUpdatedAt: string | null;
  selectedManifest: Manifest | null;
  lastImportedSha256: string | null;
  lastImportedManifest: Manifest | null;
  localSelectionAvailable: boolean;
  importInProgress: boolean;
  note: string;
  message?: string;
};
function stamp(value: string | null | undefined) {
  if (!value) return "неизвестно";
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toLocaleString("ru-RU") : "неизвестно";
}

export function DebianTrackerClient() {
  const [data, setData] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<"upload" | "select" | "disable" | null>(null);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  async function load() {
    setLoading(true);
    try {
      const response = await fetch("/api/settings/debian-tracker", { cache: "no-store" });
      const result = await readApiResponse(response) as Status;
      if (!response.ok || !result.ok) throw new Error(result.message || "Не удалось проверить источник Debian.");
      setData(result);
    } catch (error) {
      setMessage({ text: errorMessage(error, "Не удалось получить состояние Debian CVE."), error: true });
    } finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);

  async function run(action: "upload" | "select" | "disable") {
    if (!data || busy) return;
    setBusy(action);
    setMessage(null);
    try {
      const isUpload = action === "upload";
      const response = await fetch("/api/settings/debian-tracker", {
        method: isUpload ? "POST" : "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(isUpload ? {} : {
          approved: true,
          selectedSha256: action === "select" ? data.lastImportedSha256 : null,
          expectedSha256: data.selectedSha256,
        }),
      });
      const result = await readApiResponse(response) as Status;
      if (!response.ok || !result.ok) throw new Error(result.message || "Операция не выполнена.");
      setData(result);
      setMessage({ text: result.message ?? "Настройки Debian обновлены.", error: false });
    } catch (error) {
      setMessage({ text: errorMessage(error, "Не удалось изменить источник Debian."), error: true });
      void load();
    } finally { setBusy(null); }
  }

  const candidate = data?.lastImportedManifest;
  const active = data?.selectedManifest;
  const selected = data?.selectedSha256;
  const candidateAvailable = Boolean(candidate && data?.lastImportedSha256 &&
    data?.lastImportedSha256 !== selected);
  const noActions = busy !== null || loading;
  const offline = data?.mode === "offline";
  const candidateAgeHours = candidate ? Math.max(0, (Date.now() - Date.parse(candidate.capturedAt)) / 3600000) : null;
  const candidateStale = candidateAgeHours !== null && (candidateAgeHours > (data?.maxImportAgeHours ?? 168) || !Number.isInteger(data?.maxImportAgeHours) || (data?.maxImportAgeHours ?? 168) < 1 || (data?.maxImportAgeHours ?? 168) > 8760);

  return (
    <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5" aria-labelledby="debian-tracker-title">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex gap-3">
          <Database size={21} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div>
            <h2 id="debian-tracker-title" className="text-xl font-semibold text-white">Debian Security Tracker</h2>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">
              Предварительная сверка применимости CVE для Debian по исходному пакету и его версии.
              Загрузка выполняется только на сервере HCP; на целевых машинах ничего устанавливать не требуется.
              Адрес источника строго задан в платформе.
            </p>
          </div>
        </div>
        <span className="w-fit shrink-0 rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-semibold text-slate-200">
          {selected ? active ? "Снимок выбран" : "Источник недоступен" : "Отключено"}
        </span>
      </div>
      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <div className="rounded-md border border-slate-800 bg-slate-900/60 p-4">
          <p className="text-sm font-semibold text-slate-100">Источник новых CVE-отчётов</p>
          <p className="mt-1 text-sm text-slate-300">{selected ? active
            ? "Получен: " + stamp(active.capturedAt) + " · " + active.sourcePackageCount + " исходных пакетов"
            : "Закреплённый снимок не удалось проверить. Предварительный вывод будет недоступен."
            : "Не выбран. Основная CVE-проверка Trivy работает независимо."}</p>
          {selected ? <p className="mt-2 break-all font-mono text-xs text-slate-500">SHA-256 {selected}</p> : null}
        </div>
        <div className="rounded-md border border-slate-800 bg-slate-900/60 p-4">
          <p className="text-sm font-semibold text-slate-100">Последний импортированный снимок</p>
          <p className="mt-1 text-sm text-slate-300">{candidate
            ? stamp(candidate.capturedAt) + " · " + (candidate.bytes / (1024 * 1024)).toFixed(1) + " МиБ · " + candidate.issueCount + " записей"
            : data?.lastImportedSha256 ? "Снимок отсутствует или повреждён." : "База ещё не загружена в HCP."}</p>
          {candidate ? <p className="mt-2 break-all font-mono text-xs text-slate-500">SHA-256 {candidate.sha256}</p> : null}
        </div>
      </div>
      <div className="mt-4 flex flex-wrap gap-3">
        <Button onClick={() => void run("upload")} disabled={noActions || offline}>
          <RefreshCw size={16} className={busy === "upload" ? "animate-spin" : ""} aria-hidden="true" />
          {busy === "upload" ? "Загружаем и проверяем…" : "Загрузить с Debian"}
        </Button>
        {candidateAvailable ? <Button variant="secondary" onClick={() => void run("select")} disabled={noActions || candidateStale}>
          Выбрать снимок для CVE-сверки
        </Button> : null}
        {selected ? <Button variant="secondary" onClick={() => void run("disable")} disabled={noActions}>
          Отключить сверку Debian
        </Button> : null}
        <Button variant="secondary" onClick={() => void load()} disabled={noActions}>Обновить состояние</Button>
      </div>
      {busy === "upload" ? <p role="status" className="mt-3 text-sm text-sky-200">
        Идёт загрузка и проверка полной базы на контроллере. Действующий снимок не изменяется до отдельного подтверждения.
      </p> : null}
      {offline ? <p className="mt-3 text-sm text-amber-200">
        Выбран локальный режим CVE-баз. Для сетевой загрузки сначала включите сетевой режим Trivy выше.
      </p> : null}
      {candidateAvailable && candidateStale ? <p className="mt-3 text-sm text-amber-200">
        Превышен допустимый возраст локального снимка или политика некорректна. Повторите загрузку или проверьте настройки контроллера. Недавний импорт не доказывает актуальность у Debian.
      </p> : null}
      {message ? <p role="status" className={"mt-3 rounded-md border px-3 py-2 text-sm " +
        (message.error ? "border-rose-400/30 text-rose-200" : "border-sky-400/30 text-sky-100")}>{message.text}</p> : null}
      <div className="mt-4 flex items-start gap-2 border-t border-slate-800 pt-4 text-sm leading-6 text-amber-100">
        <ShieldAlert size={18} className="mt-1 shrink-0" aria-hidden="true" />
        <p>Снимки неизменяемы. Повторная загрузка идентичных байтов не обновляет дату снимка. SHA-256 подтверждает целостность, но не подпись Debian или полноту CVE. Сверка не меняет находки Trivy и не разрешает автоматическое исправление пакетов.</p>
      </div>
    </section>
  );
}
