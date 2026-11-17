"use client";

import { Select } from "@/components/ui/select";

import { CheckCircle2, FileWarning, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useFeedbackMessage } from "@/components/ui/feedback";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button } from "@/components/ui/button";
import { ASTRA_BASELINE_DATASTREAM, ASTRA_BASELINE_PROFILE } from "@/lib/scap-presets";

type OpenScapPolicy = {
  groupName: string;
  datastream: string;
  profile: string;
  updatedAt: string;
};

type OpenScapException = {
  id: string;
  groupName: string;
  ruleId: string;
  reason: string;
  expiresAt: string;
  active: boolean;
};

type SettingsPayload = {
  ok?: boolean;
  message?: string;
  inventoryGroups?: string[];
  policies?: OpenScapPolicy[];
  exceptions?: OpenScapException[];
};

const inputClassName = "mt-1 h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-sky-300 focus:ring-2 focus:ring-sky-300/20";

function dateTimeValue(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function dateValueInFuture() {
  const date = new Date();
  date.setDate(date.getDate() + 30);
  return date.toISOString().slice(0, 10);
}

export function OpenScapPoliciesClient() {
  const [settings, setSettings] = useState<SettingsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useFeedbackMessage();
  const [policyGroup, setPolicyGroup] = useState("linux_hosts");
  const [preset, setPreset] = useState("astra");
  const [datastream, setDatastream] = useState("");
  const [profile, setProfile] = useState("");
  const [exceptionGroup, setExceptionGroup] = useState("linux_hosts");
  const [ruleId, setRuleId] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState(dateValueInFuture);

  function selectGroup(groupName: string, policies = settings?.policies ?? []) {
    const saved = policies.find((item) => item.groupName === groupName);
    setPolicyGroup(groupName);
    setPreset(!saved || (saved.datastream === ASTRA_BASELINE_DATASTREAM && saved.profile === ASTRA_BASELINE_PROFILE) ? "astra" : "custom");
    setDatastream(saved?.datastream ?? "");
    setProfile(saved?.profile ?? "");
  }

  async function load(announce = false) {
    setLoading(true);
    try {
      const response = await fetch("/api/settings/openscap-policies", { cache: "no-store" });
      const payload = await readApiResponse(response) as SettingsPayload;
      if (!response.ok || !payload.ok) throw new Error(payload.message || "Не удалось получить настройки.");
      setSettings(payload);
      const firstGroup = payload.inventoryGroups?.[0] ?? "linux_hosts";
      selectGroup(payload.inventoryGroups?.includes(policyGroup) ? policyGroup : firstGroup, payload.policies);
      setExceptionGroup((current) => payload.inventoryGroups?.includes(current) ? current : firstGroup);
      if (announce) setMessage("Сведения обновлены.", "success");
    } catch (error) {
      setMessage(errorMessage(error, "Не удалось загрузить политики OpenSCAP."));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function submit(body: Record<string, string>) {
    setSaving(true);
    setMessage("");
    try {
      const response = await fetch("/api/settings/openscap-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await readApiResponse(response) as SettingsPayload;
      if (!response.ok || !payload.ok) throw new Error(payload.message || "Не удалось получить настройки.");
      setSettings(payload);
      setMessage(payload.message ?? (payload.ok ? "Настройка сохранена." : "Не удалось сохранить настройку."), payload.ok ? "success" : "error");
      return Boolean(payload.ok);
    } catch (error) {
      setMessage(errorMessage(error, "Не удалось сохранить настройку OpenSCAP."));
      return false;
    } finally {
      setSaving(false);
    }
  }

  async function remove(body: Record<string, string>) {
    setSaving(true);
    setMessage("");
    try {
      const response = await fetch("/api/settings/openscap-policies", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await readApiResponse(response) as SettingsPayload;
      if (!response.ok || !payload.ok) throw new Error(payload.message || "Не удалось получить настройки.");
      setSettings(payload);
      if (body.kind === "profile" && body.groupName === policyGroup) selectGroup(policyGroup, payload.policies);
      setMessage(payload.message ?? (payload.ok ? "Настройка удалена." : "Не удалось удалить настройку."), payload.ok ? "success" : "error");
    } catch (error) {
      setMessage(errorMessage(error, "Не удалось удалить настройку OpenSCAP."));
    } finally {
      setSaving(false);
    }
  }

  const groups = settings?.inventoryGroups ?? ["linux_hosts"];
  const savedPolicy = settings?.policies?.find((item) => item.groupName === policyGroup);

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>

          <h1 className="mt-2 text-3xl font-semibold text-white">OpenSCAP и исключения</h1>

        </div>
        <Button variant="secondary" onClick={() => load(true)} disabled={loading || saving}><RefreshCw size={16} className={loading ? "animate-spin" : ""} aria-hidden="true" />Обновить</Button>
      </header>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5" aria-labelledby="profile-title">
        <div className="flex gap-3">
          <ShieldCheck size={22} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div>
            <h2 id="profile-title" className="text-xl font-semibold text-white">1. Профиль для группы</h2>
            <p className="mt-1 text-sm leading-6 text-slate-400">Назначьте профиль перед запуском OpenSCAP.</p>
          </div>
        </div>
        <form className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-3" onSubmit={(event) => { event.preventDefault(); void submit({ kind: "profile", groupName: policyGroup, datastream: preset === "astra" ? ASTRA_BASELINE_DATASTREAM : datastream, profile: preset === "astra" ? ASTRA_BASELINE_PROFILE : profile }); }}>
          <label className="min-w-0 text-sm text-slate-300">Группа хостов
            <Select aria-label="Группа профиля" className={inputClassName} value={policyGroup} onValueChange={selectGroup} disabled={saving || loading}>{groups.map((group) => <option key={group} value={group}>{group}{settings?.policies?.some((item) => item.groupName === group) ? " · настроено" : ""}</option>)}</Select>
          </label>
          <label className="min-w-0 text-sm text-slate-300 lg:col-span-2">Набор проверок
            <Select aria-label="Набор проверок" className={inputClassName} value={preset} onValueChange={(value) => setPreset(value)} disabled={saving || loading}><option value="custom">Собственный SCAP / SSG</option><option value="astra">Astra Linux — базовые проверки HCP</option></Select>
          </label>
          {preset === "astra" ? <details className="text-xs leading-5 text-slate-400 lg:col-span-3"><summary className="cursor-pointer text-sky-200">О профиле HCP</summary><p className="mt-2">18 правил настроек Astra. На хосте нужен OpenSCAP с SCE. Это авторский профиль HCP, а не сертификация ФСТЭК или CIS.</p></details> : <>
          <label className="min-w-0 text-sm text-slate-300">Путь к datastream
            <input className={inputClassName} placeholder="Полный путь к SCAP datastream на хосте" value={datastream} onChange={(event) => setDatastream(event.target.value)} required />
          </label>
          <label className="min-w-0 text-sm text-slate-300">Идентификатор профиля
            <input className={inputClassName} placeholder="Идентификатор из oscap info" value={profile} onChange={(event) => setProfile(event.target.value)} required />
          </label>
          </>}
          <div className="lg:col-span-3"><Button type="submit" disabled={saving || loading}><CheckCircle2 size={16} aria-hidden="true" />{saving ? "Сохраняем…" : "Сохранить профиль"}</Button></div>
        </form>

        {savedPolicy ? <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-3"><p className="text-xs text-slate-400">Сохранён для {policyGroup} · {dateTimeValue(savedPolicy.updatedAt)}</p><Button type="button" variant="danger" className="h-8 px-3 text-xs" disabled={saving || loading} onClick={() => void remove({ kind: "profile", groupName: policyGroup })}><Trash2 size={14} aria-hidden="true" />Удалить назначение</Button></div> : <p className="mt-4 text-xs text-slate-400">Для этой группы профиль ещё не сохранён.</p>}
      </section>

      <section className="rounded-md border border-amber-400/25 bg-amber-500/5 p-5" aria-labelledby="exception-title">
        <div className="flex gap-3"><FileWarning size={22} className="mt-0.5 shrink-0 text-amber-200" aria-hidden="true" /><div><h2 id="exception-title" className="text-xl font-semibold text-white">2. Исключения</h2><p className="mt-1 text-sm leading-6 text-amber-100">Укажите правило, причину и срок. Исходный риск останется в отчёте.</p></div></div>
        <details className="mt-4 rounded-md border border-amber-400/20 p-3"><summary className="cursor-pointer text-sm font-semibold text-sky-200">Добавить исключение</summary>
        <form className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2" onSubmit={async (event) => { event.preventDefault(); const ok = await submit({ kind: "exception", groupName: exceptionGroup, ruleId, reason, expiresAt: `${expiresAt}T23:59:59.999Z` }); if (ok) { setRuleId(""); setReason(""); } }}>
          <label className="min-w-0 text-sm text-slate-300">Группа inventory<Select className={inputClassName} value={exceptionGroup} onValueChange={(value) => setExceptionGroup(value)}>{groups.map((group) => <option key={group} value={group}>{group}</option>)}</Select></label>
          <label className="min-w-0 text-sm text-slate-300">Идентификатор правила из отчёта<input className={inputClassName} placeholder="xccdf_org.ssgproject.content_rule_…" value={ruleId} onChange={(event) => setRuleId(event.target.value)} required /></label>
          <label className="min-w-0 text-sm text-slate-300 lg:col-span-1">Дата окончания<input className={inputClassName} type="date" value={expiresAt} min={new Date().toISOString().slice(0, 10)} onChange={(event) => setExpiresAt(event.target.value)} required /></label>
          <label className="min-w-0 text-sm text-slate-300 lg:col-span-1">Причина исключения<textarea className="mt-1 min-h-24 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-sky-300 focus:ring-2 focus:ring-sky-300/20" value={reason} onChange={(event) => setReason(event.target.value)} minLength={10} maxLength={500} required /></label>
          <div className="lg:col-span-2"><Button type="submit" disabled={saving || loading}><CheckCircle2 size={16} aria-hidden="true" />{saving ? "Сохраняем…" : "Сохранить исключение"}</Button></div>
        </form>
        </details>
        <div className="relative mt-6 overflow-x-auto rounded-md border border-amber-400/20">
          <table className="min-w-[840px] w-full text-left text-sm"><thead className="border-b border-amber-400/15 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-3 py-3">Группа</th><th className="px-3 py-3">Правило</th><th className="px-3 py-3">Причина</th><th className="px-3 py-3">До</th><th className="px-3 py-3"><span className="sr-only">Действия</span></th></tr></thead><tbody>{(settings?.exceptions ?? []).length ? (settings?.exceptions ?? []).map((item) => <tr key={item.id} className="border-b border-slate-800/80 align-top last:border-0"><td className="px-3 py-3 font-semibold text-slate-100">{item.groupName}</td><td className="px-3 py-3 break-all text-slate-300">{item.ruleId}</td><td className="max-w-md px-3 py-3 leading-6 text-slate-400">{item.reason}</td><td className={`px-3 py-3 ${item.active ? "text-amber-100" : "text-slate-500"}`}>{dateTimeValue(item.expiresAt)}{item.active ? "" : " · истекло"}</td><td className="px-3 py-3 text-right"><Button type="button" variant="danger" className="h-8 px-3 text-xs" disabled={saving} onClick={() => void remove({ kind: "exception", id: item.id })}><Trash2 size={14} aria-hidden="true" />Удалить</Button></td></tr>) : <tr><td colSpan={5} className="px-3 py-5 text-slate-500">Согласованных исключений нет.</td></tr>}</tbody></table>
        </div>
      </section>

      {message ? <p role="status" className="rounded-md border border-sky-400/25 bg-sky-500/10 px-3 py-2 text-sm text-sky-100">{message}</p> : null}
    </div>
  );
}
