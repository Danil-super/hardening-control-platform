"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import type { AstraOvalConfig } from "@/lib/astra-oval-config";

type Policy = { groupName: string; config: AstraOvalConfig; updatedAt: string };
type Payload = { ok?: boolean; message?: string; inventoryGroups?: string[]; policies?: Policy[] };
const initial: AstraOvalConfig = { mode: "local", path: "/usr/share/oval/db.xml", url: "", sha256: "", releasePattern: "*", architectures: [], maxAgeDays: 30 };
const inputClass = "mt-1 w-full min-w-0 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-300";

export function AstraOvalClient() {
  const [data, setData] = useState<Payload>({});
  const [group, setGroup] = useState("linux_hosts");
  const [config, setConfig] = useState<AstraOvalConfig>(initial);
  const [architectures, setArchitectures] = useState("");
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState("");
  const update = (values: Partial<AstraOvalConfig>) => setConfig((previous) => ({ ...previous, ...values }));

  useEffect(() => {
    let active = true;
    fetch("/api/settings/astra-oval", { cache: "no-store" }).then(async (response) => {
      const payload = await response.json() as Payload;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось прочитать источники OVAL.");
      if (active) setData(payload);
    }).catch((error) => { if (active) setMessage(error instanceof Error ? error.message : "Ошибка загрузки."); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, []);

  async function saveOrRemove(method: "POST" | "DELETE", groupName = group) {
    setBusy(true); setMessage("");
    try {
      const response = await fetch("/api/settings/astra-oval", { method, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ groupName, config: { ...config, architectures: architectures.split(/[\s,]+/).filter(Boolean) } }) });
      const payload = await response.json() as Payload;
      if (!response.ok || !payload.ok) throw new Error(payload.message ?? "Не удалось сохранить источник.");
      setData(payload); setMessage(payload.message ?? "Сохранено.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Ошибка сохранения."); }
    finally { setBusy(false); }
  }

  return <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5" aria-labelledby="astra-oval-title">
    <h2 id="astra-oval-title" className="text-xl font-semibold text-white">CVE пакетов Astra</h2>
    <p className="mt-2 text-sm leading-6 text-slate-400">OpenSCAP проверяет установленные пакеты по определениям выбранной OVAL-базы. Назначьте источник группе хостов. Для разных выпусков можно создать отдельные группы и источники.</p>
    <form className="mt-5 grid gap-4 md:grid-cols-2" onSubmit={(event) => { event.preventDefault(); void saveOrRemove("POST"); }}>
      <label className="min-w-0 text-sm text-slate-300">Группа хостов
        <select className={inputClass} value={group} onChange={(event) => setGroup(event.target.value)} required>
          {(data.inventoryGroups ?? ["linux_hosts"]).map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      </label>
      <label className="text-sm text-slate-300">Источник базы
        <select className={inputClass} value={config.mode} onChange={(event) => update({ mode: event.target.value as AstraOvalConfig["mode"] })}>
          <option value="local">Локальный XML на проверяемом хосте</option><option value="online">Интернет или внутреннее HTTPS-зеркало</option>
        </select>
      </label>
      <label className="min-w-0 text-sm text-slate-300 md:col-span-2">{config.mode === "local" ? "Полный путь к XML на хосте" : "HTTPS-адрес XML-базы"}
        <input className={inputClass} value={config.mode === "local" ? config.path : config.url} onChange={(event) => update(config.mode === "local" ? { path: event.target.value } : { url: event.target.value })} required placeholder={config.mode === "local" ? "/usr/share/oval/db.xml" : "https://mirror.example/oval/astra.xml"} />
        <span className="mt-1 block text-xs leading-5 text-slate-400">{config.mode === "local" ? "Используется файл на каждой ВМ. Интернет при проверке не нужен." : "Файл скачивает управляющая машина и временно передаёт по SSH. Проверяемой ВМ интернет не нужен. Требуется прямой адрес XML без авторизации и параметров запроса."}</span>
      </label>
      <label className="min-w-0 text-sm text-slate-300 md:col-span-2">Ожидаемый SHA-256 {config.mode === "local" ? "(необязательно)" : "(обязательно)"}
        <input className={inputClass} value={config.sha256} onChange={(event) => update({ sha256: event.target.value })} required={config.mode === "online"} pattern="[a-fA-F0-9]{64}" placeholder="64 шестнадцатеричных символа" />
        <span className="mt-1 block text-xs leading-5 text-slate-400">Сверьте сумму по доверенному источнику. Совпадение SHA-256 подтверждает байты файла, но не подпись производителя.</span>
      </label>
      <label className="text-sm text-slate-300">Область применения: выпуск Astra
        <input className={inputClass} value={config.releasePattern} onChange={(event) => update({ releasePattern: event.target.value })} required placeholder="Например, 1.7.*" />
        <span className="mt-1 block text-xs leading-5 text-slate-400">Точный выпуск, ветка с .* или *. Это ваше ограничение; условия внутри OVAL также проверяет сканер. * не подтверждает охват всех выпусков.</span>
      </label>
      <label className="text-sm text-slate-300">Максимальный возраст базы, дней
        <input className={inputClass} type="number" min={1} max={3650} value={config.maxAgeDays} onChange={(event) => update({ maxAgeDays: Number(event.target.value) })} required />
        <span className="mt-1 block text-xs leading-5 text-slate-400">Используется дата внутри базы. Неизвестная или устаревшая дата отмечается в отчёте.</span>
      </label>
      <label className="text-sm text-slate-300 md:col-span-2">Архитектуры (необязательно)
        <input className={inputClass} value={architectures} onChange={(event) => setArchitectures(event.target.value)} placeholder="Например, x86_64, aarch64 — значения uname -m" />
      </label>
      <div className="md:col-span-2"><Button type="submit" disabled={busy || !data.ok}>{busy ? "Обработка…" : "Сохранить источник"}</Button></div>
    </form>
    {message ? <p className="mt-3 break-words text-sm leading-6 text-sky-100" role="status">{message}</p> : null}
    <div className="mt-5 space-y-3">
      {(data.policies ?? []).map((policy) => <div key={policy.groupName} className="rounded-md border border-slate-800 p-3 text-sm">
        <p className="font-semibold text-slate-100">{policy.groupName} · {policy.config.mode === "local" ? "локальная база" : "HTTPS-база"} · выпуск {policy.config.releasePattern}</p>
        <p className="mt-1 break-all text-slate-400">{policy.config.mode === "local" ? policy.config.path : policy.config.url}</p>
        <div className="mt-3 flex flex-wrap gap-3">
          <Button variant="secondary" disabled={busy} onClick={() => { setGroup(policy.groupName); setConfig(policy.config); setArchitectures(policy.config.architectures.join(", ")); setMessage("Источник открыт для редактирования в форме выше."); }}>Изменить</Button>
          <Button variant="secondary" disabled={busy} onClick={() => void saveOrRemove("DELETE", policy.groupName)}>Удалить</Button>
        </div>
      </div>)}
    </div>
    <p className="mt-4 text-sm leading-6 text-slate-400">После сохранения откройте «Хосты» → «Проверить CVE Astra по OVAL». Полнота относится к определениям выбранного файла. Отсутствие находок не гарантирует отсутствие всех CVE.</p>
  </section>;
}
