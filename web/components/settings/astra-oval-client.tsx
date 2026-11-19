"use client";

import { Select } from "@/components/ui/select";

import { useEffect, useState } from "react";
import { useFeedbackMessage } from "@/components/ui/feedback";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button, LinkButton } from "@/components/ui/button";
import type { AstraOvalConfig } from "@/lib/astra-oval-config";
import type { OvalPreparationStatus } from "@/lib/astra-oval-preparation";

type Policy = { groupName: string; config: AstraOvalConfig; updatedAt: string; preparation?: OvalPreparationStatus };
type Payload = { ok?: boolean; message?: string; inventoryGroups?: string[]; policies?: Policy[] };
const initial: AstraOvalConfig = { mode: "online", path: "/usr/share/oval/db.xml", url: "", sha256: "", releasePattern: "*", architectures: [], maxAgeDays: 30, sourceName: "", sourceReference: "", sourceReviewedAt: null, evidenceProjection: "bounded" };
const inputClass = "mt-1 w-full min-w-0 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-300";

export function AstraOvalClient() {
  const [data, setData] = useState<Payload>({});
  const [group, setGroup] = useState("linux_hosts");
  const [config, setConfig] = useState<AstraOvalConfig>(initial);
  const [architectures, setArchitectures] = useState("");
  const [busy, setBusy] = useState(true);
  const [catalogBusy, setCatalogBusy] = useState(false);
  const [catalogRelease, setCatalogRelease] = useState<"1.7" | "1.8">("1.7");
  const [refreshKey, setRefreshKey] = useState(0);
  const [message, setMessage] = useFeedbackMessage();
  const preparing = (data.policies ?? []).some(policy => policy.preparation?.state === "preparing");
  const update = (values: Partial<AstraOvalConfig>) => setConfig((previous) => ({ ...previous, ...values }));

  useEffect(() => {
    let active = true;
    fetch("/api/settings/astra-oval", { cache: "no-store" }).then(async (response) => {
      const payload = await readApiResponse(response) as Payload;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать источники OVAL.");
      if (active) setData(payload);
    }).catch((error) => { if (active) setMessage(errorMessage(error, "Ошибка загрузки. Проверьте соединение.")); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [refreshKey]);

  useEffect(() => {
    if (!preparing) return;
    const timer = setInterval(() => setRefreshKey(value => value + 1), 3000);
    return () => clearInterval(timer);
  }, [preparing]);

  async function refreshOfficialCatalog() {
    setCatalogBusy(true);
    setMessage("");
    try {
      const response = await fetch("/api/settings/astra-oval/catalog", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ groupName: group, release: catalogRelease }),
      });
      const payload = await readApiResponse(response) as {
        ok?: boolean; message?: string; sourceSaved?: boolean;
        policy?: Policy; preparation?: OvalPreparationStatus;
      };
      if (payload.policy) {
        setConfig(payload.policy.config);
        setArchitectures(payload.policy.config.architectures.join(", "));
        setRefreshKey(value => value + 1);
      }
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось обновить базу Astra.");
      setMessage(payload.message ?? "Обновление базы запущено.", payload.preparation?.state === "ready" ? "success" : "info");
    } catch (error) {
      setMessage(errorMessage(error, "Не удалось получить сведения изготовителя."));
    } finally {
      setCatalogBusy(false);
    }
  }

  async function saveOrRemove(method: "POST" | "DELETE", groupName = group) {
    setBusy(true); setMessage("");
    try {
      const savedConfig = {
        ...config,
        architectures: architectures.split(/[\s,]+/).filter(Boolean),
        sourceName: config.sourceName.trim() || (config.mode === "online" ? "Указанный HTTPS-источник OVAL" : "Локальная доверенная копия OVAL"),
        sourceReference: config.sourceReference.trim() || (config.mode === "online" ? config.url.trim() : config.path.trim()),
      };
      const response = await fetch("/api/settings/astra-oval", { method, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ groupName, config: savedConfig }) });
      const payload = await readApiResponse(response) as Payload;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось сохранить источник.");
      setData(payload); setMessage(payload.message ?? (method === "DELETE" ? "Источник удалён." : "Источник сохранён."), "success");
    } catch (error) { setMessage(errorMessage(error, "Ошибка сохранения. Проверьте соединение.")); }
    finally { setBusy(false); }
  }

  return <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5" aria-labelledby="astra-oval-title">
    <h2 id="astra-oval-title" className="text-xl font-semibold text-white">CVE Astra — OVAL</h2>
    <p className="mt-1 text-sm text-slate-400">Выберите группу и выпуск. HCP сам получит адрес, скачает и проверит базу производителя.</p>
    <form className="mt-4 space-y-4"
      onInvalidCapture={(event) => { (event.target as HTMLElement).closest("details")?.setAttribute("open", ""); }}
      onSubmit={(event) => { event.preventDefault(); void saveOrRemove("POST"); }}>
      <div className="grid items-end gap-3 md:grid-cols-[1fr_1fr_auto]">
        <label className="min-w-0 text-sm text-slate-300">Группа хостов
          <Select className={inputClass} value={group} onValueChange={(value) => setGroup(value)} disabled={busy || catalogBusy || preparing} required>
            {(data.inventoryGroups ?? ["linux_hosts"]).map((name) => <option key={name} value={name}>{name}</option>)}
          </Select>
        </label>
        <label className="min-w-0 text-sm text-slate-300">Выпуск Astra
          <Select className={inputClass} value={catalogRelease} disabled={busy || catalogBusy || preparing}
            onValueChange={value => setCatalogRelease(value as "1.7" | "1.8")}>
            <option value="1.7">1.7, x86-64</option>
            <option value="1.8">1.8, x86-64</option>
          </Select>
        </label>
        <Button type="button" disabled={busy || catalogBusy || preparing || !data.ok}
          onClick={() => void refreshOfficialCatalog()}>
          {catalogBusy ? "Связь с Astra…" : preparing ? "Загрузка и проверка…" : "Обновить базу Astra"}
        </Button>
      </div>
      {config.sha256 && <p className="text-sm text-slate-300">Выбрано: {config.mode === "local" ? "локальный XML" : config.sourceName || "HTTPS-база"} · выпуск {config.releasePattern}</p>}
      <details id="astra-oval-manual" className="rounded-md border border-slate-800 bg-slate-900/60 p-3">
        <summary className="cursor-pointer text-sm font-semibold text-slate-200">Адрес базы и ручная настройка</summary>
        <p className="mt-2 text-xs leading-5 text-slate-400">Для внутреннего зеркала или локального XML. SHA-256 проверяет байты файла, но не подпись производителя.</p>
        <div className="mt-3 grid grid-cols-1 gap-4 md:grid-cols-2">
          <label className="min-w-0 text-sm text-slate-300">Источник базы
            <Select className={inputClass} value={config.mode} onValueChange={(value) => update({ mode: value as AstraOvalConfig["mode"] })}>
              <option value="online">HTTPS-источник или внутреннее зеркало</option><option value="local">Локальный XML на проверяемом хосте</option>
            </Select>
          </label>
          <label className="min-w-0 text-sm text-slate-300 md:col-span-2">{config.mode === "local" ? "Полный путь к XML на хосте" : "HTTPS-адрес XML-базы"}
            <input className={inputClass} value={config.mode === "local" ? config.path : config.url} onChange={(event) => update(config.mode === "local" ? { path: event.target.value } : { url: event.target.value })} required placeholder={config.mode === "local" ? "/usr/share/oval/db.xml" : "https://mirror.example/oval/astra.xml"} />
            <span className="mt-1 block text-xs leading-5 text-slate-400">{config.mode === "local" ? "Файл должен быть на каждом проверяемом хосте." : "HCP скачает XML и передаст хосту по SSH. Нужен прямой HTTPS-адрес без авторизации и параметров запроса."}</span>
          </label>
          <label className="min-w-0 text-sm text-slate-300 md:col-span-2">Ожидаемый SHA-256
            <input className={inputClass} value={config.sha256} onChange={(event) => update({ sha256: event.target.value })} required pattern="[a-fA-F0-9]{64}" placeholder="64 шестнадцатеричных символа" />
          </label>
          <label className="min-w-0 text-sm text-slate-300">Область применения: выпуск Astra
            <input className={inputClass} value={config.releasePattern} onChange={(event) => update({ releasePattern: event.target.value })} required placeholder="Например, 1.7.*" />
            <span className="mt-1 block text-xs leading-5 text-slate-400">Версия ОС из /etc/astra_version, например 1.7.*.</span>
          </label>
          <label className="min-w-0 text-sm text-slate-300">Название доверенного источника
            <input className={inputClass} value={config.sourceName} onChange={(event) => update({ sourceName: event.target.value })} placeholder="Например, бюллетени производителя Astra" />
          </label>
          <label className="min-w-0 text-sm text-slate-300">Ссылка или ID источника
            <input className={inputClass} value={config.sourceReference} onChange={(event) => update({ sourceReference: event.target.value })} placeholder="URL, номер бюллетеня или ID внутреннего реестра" />
          </label>
          <label className="min-w-0 text-sm text-slate-300">Максимальный возраст базы, дней
            <input className={inputClass} type="number" min={1} max={3650} value={config.maxAgeDays} onChange={(event) => update({ maxAgeDays: Number(event.target.value) })} required />
          </label>
          <label className="min-w-0 text-sm text-slate-300">Архитектуры (необязательно)
            <input className={inputClass} value={architectures} onChange={(event) => setArchitectures(event.target.value)} placeholder="Например, x86_64, aarch64 — значения uname -m" />
          </label>
        </div>
        <Button type="submit" className="mt-4" variant="secondary" disabled={busy || catalogBusy || preparing || !data.ok || !config.sha256}>{busy ? "Обработка…" : "Сохранить ручной источник"}</Button>
      </details>
    </form>
    {message ? <p className="mt-3 break-words text-sm leading-6 text-sky-100" role="status">{message}</p> : null}
    <div className="mt-5 space-y-3">
      {(data.policies ?? []).map((policy) => <div key={policy.groupName} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-slate-800 p-3 text-sm">
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-slate-100">{policy.groupName} · {policy.config.mode === "local" ? "локальная база" : "HTTPS-база"} · выпуск {policy.config.releasePattern}</p>
          <p className={`mt-1 text-sm ${policy.preparation?.state === "ready" ? "text-emerald-200" : policy.preparation?.state === "failed" ? "text-amber-200" : "text-slate-300"}`} role="status">
            {policy.preparation?.state === "ready" ? "База готова" : policy.preparation?.state === "preparing" ? "Загрузка и проверка базы…" : policy.preparation?.state === "local" ? "XML будет проверен на хосте" : policy.preparation?.state === "failed" ? "Ошибка подготовки базы" : "База не загружена"}
            {policy.preparation?.generatedAt ? ` · дата базы: ${new Date(policy.preparation.generatedAt).toLocaleString("ru-RU")}` : ""}
          </p>
          {policy.preparation?.state === "failed" ? <p className="mt-1 text-xs text-amber-100">{policy.preparation.message}</p> : null}
          <details className="mt-2 text-xs text-slate-400">
            <summary className="cursor-pointer">Реквизиты источника</summary>
            <p className="mt-2 break-all">{policy.config.mode === "local" ? policy.config.path : policy.config.url}</p>
            <p className="mt-1 break-all">Источник: {policy.config.sourceName || "не зафиксирован"} · {policy.config.sourceReference || "не зафиксирован"} · сверено: {policy.config.sourceReviewedAt ? new Date(policy.config.sourceReviewedAt).toLocaleString("ru-RU") : "нет"}</p>
          </details>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button variant="secondary" disabled={busy || catalogBusy || preparing} onClick={() => { setGroup(policy.groupName); setConfig(policy.config); setCatalogRelease(policy.config.releasePattern.startsWith("1.8") ? "1.8" : "1.7"); setArchitectures(policy.config.architectures.join(", ")); setMessage("Источник открыт для редактирования.", "info"); document.getElementById("astra-oval-manual")?.setAttribute("open", ""); document.getElementById("astra-oval-title")?.scrollIntoView({ block: "start" }); }}>Изменить</Button>
          <Button variant="secondary" disabled={busy || catalogBusy || preparing} onClick={() => void saveOrRemove("DELETE", policy.groupName)}>Удалить</Button>
        </div>
      </div>)}
    </div>
    <div className="mt-4"><LinkButton href="/hosts#ansible-actions" variant="secondary">Далее: проверка хостов</LinkButton></div>
  </section>;
}
