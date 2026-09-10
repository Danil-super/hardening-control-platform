"use client";

import { CheckCircle2, FileWarning, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

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
  const [message, setMessage] = useState("");
  const [policyGroup, setPolicyGroup] = useState("linux_hosts");
  const [datastream, setDatastream] = useState("/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml");
  const [profile, setProfile] = useState("xccdf_org.ssgproject.content_profile_cis_level1_server");
  const [exceptionGroup, setExceptionGroup] = useState("linux_hosts");
  const [ruleId, setRuleId] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState(dateValueInFuture);

  async function load() {
    setLoading(true);
    try {
      const response = await fetch("/api/settings/openscap-policies", { cache: "no-store" });
      const payload = await response.json() as SettingsPayload;
      setSettings(payload);
      const firstGroup = payload.inventoryGroups?.[0] ?? "linux_hosts";
      setPolicyGroup((current) => payload.inventoryGroups?.includes(current) ? current : firstGroup);
      setExceptionGroup((current) => payload.inventoryGroups?.includes(current) ? current : firstGroup);
    } catch {
      setMessage("Не удалось загрузить политики OpenSCAP.");
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
      const payload = await response.json() as SettingsPayload;
      setSettings(payload);
      setMessage(payload.message ?? (payload.ok ? "Настройка сохранена." : "Не удалось сохранить настройку."));
      return Boolean(payload.ok);
    } catch {
      setMessage("Не удалось сохранить настройку OpenSCAP.");
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
      const payload = await response.json() as SettingsPayload;
      setSettings(payload);
      setMessage(payload.message ?? (payload.ok ? "Настройка удалена." : "Не удалось удалить настройку."));
    } catch {
      setMessage("Не удалось удалить настройку OpenSCAP.");
    } finally {
      setSaving(false);
    }
  }

  const groups = settings?.inventoryGroups ?? ["linux_hosts"];

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-sky-200">Политики соответствия</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">OpenSCAP и исключения</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Для каждой группы назначается один точный SSG datastream и профиль. Временное исключение остаётся видимым в отчёте и не скрывает риск.</p>
        </div>
        <Button variant="secondary" onClick={load} disabled={loading || saving}><RefreshCw size={16} className={loading ? "animate-spin" : ""} aria-hidden="true" />Обновить</Button>
      </header>

      <section className="rounded-md border border-slate-800 bg-slate-950/70 p-5" aria-labelledby="profile-title">
        <div className="flex gap-3">
          <ShieldCheck size={22} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div>
            <h2 id="profile-title" className="text-xl font-semibold text-white">SSG-профиль для группы</h2>
            <p className="mt-1 text-sm leading-6 text-slate-400">Панель передаст эти значения в OpenSCAP только для хостов выбранной группы. Если профиль не задан, сохраняется явная настройка через переменные окружения для совместимости.</p>
          </div>
        </div>
        <form className="mt-5 grid gap-4 lg:grid-cols-3" onSubmit={(event) => { event.preventDefault(); void submit({ kind: "profile", groupName: policyGroup, datastream, profile }); }}>
          <label className="text-sm text-slate-300">Группа inventory
            <select className={inputClassName} value={policyGroup} onChange={(event) => setPolicyGroup(event.target.value)}>{groups.map((group) => <option key={group} value={group}>{group}</option>)}</select>
          </label>
          <label className="text-sm text-slate-300">Путь к datastream
            <input className={inputClassName} value={datastream} onChange={(event) => setDatastream(event.target.value)} required />
          </label>
          <label className="text-sm text-slate-300">Идентификатор профиля
            <input className={inputClassName} value={profile} onChange={(event) => setProfile(event.target.value)} required />
          </label>
          <div className="lg:col-span-3"><Button type="submit" disabled={saving || loading}><CheckCircle2 size={16} aria-hidden="true" />{saving ? "Сохраняем…" : "Сохранить профиль"}</Button></div>
        </form>

        <div className="mt-6 overflow-x-auto rounded-md border border-slate-800">
          <table className="min-w-[720px] w-full text-left text-sm">
            <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-3 py-3">Группа</th><th className="px-3 py-3">Datastream</th><th className="px-3 py-3">Профиль</th><th className="px-3 py-3"><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{(settings?.policies ?? []).length ? (settings?.policies ?? []).map((item) => <tr key={item.groupName} className="border-b border-slate-800/80 last:border-0"><td className="px-3 py-3 font-semibold text-slate-100">{item.groupName}</td><td className="px-3 py-3 break-all text-slate-400">{item.datastream}</td><td className="px-3 py-3 break-all text-slate-300">{item.profile}</td><td className="px-3 py-3 text-right"><Button type="button" variant="danger" className="h-8 px-3 text-xs" disabled={saving} onClick={() => void remove({ kind: "profile", groupName: item.groupName })}><Trash2 size={14} aria-hidden="true" />Удалить</Button></td></tr>) : <tr><td colSpan={4} className="px-3 py-5 text-slate-500">Нет сохранённых профилей: будет использована конфигурация окружения.</td></tr>}</tbody>
          </table>
        </div>
      </section>

      <section className="rounded-md border border-amber-400/25 bg-amber-500/5 p-5" aria-labelledby="exception-title">
        <div className="flex gap-3"><FileWarning size={22} className="mt-0.5 shrink-0 text-amber-200" aria-hidden="true" /><div><h2 id="exception-title" className="text-xl font-semibold text-white">Согласованное исключение</h2><p className="mt-1 text-sm leading-6 text-amber-100">Добавляйте только для конкретного правила SSG, с причиной и сроком. Исключение отмечается в отчёте; исходный результат проверки, риск и количество проблем сохраняются.</p></div></div>
        <form className="mt-5 grid gap-4 lg:grid-cols-2" onSubmit={async (event) => { event.preventDefault(); const ok = await submit({ kind: "exception", groupName: exceptionGroup, ruleId, reason, expiresAt: `${expiresAt}T23:59:59.999Z` }); if (ok) { setRuleId(""); setReason(""); } }}>
          <label className="text-sm text-slate-300">Группа inventory<select className={inputClassName} value={exceptionGroup} onChange={(event) => setExceptionGroup(event.target.value)}>{groups.map((group) => <option key={group} value={group}>{group}</option>)}</select></label>
          <label className="text-sm text-slate-300">Идентификатор правила из отчёта<input className={inputClassName} placeholder="xccdf_org.ssgproject.content_rule_…" value={ruleId} onChange={(event) => setRuleId(event.target.value)} required /></label>
          <label className="text-sm text-slate-300 lg:col-span-1">Дата окончания<input className={inputClassName} type="date" value={expiresAt} min={new Date().toISOString().slice(0, 10)} onChange={(event) => setExpiresAt(event.target.value)} required /></label>
          <label className="text-sm text-slate-300 lg:col-span-1">Причина исключения<textarea className="mt-1 min-h-24 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-sky-300 focus:ring-2 focus:ring-sky-300/20" value={reason} onChange={(event) => setReason(event.target.value)} minLength={10} maxLength={500} required /></label>
          <div className="lg:col-span-2"><Button type="submit" disabled={saving || loading}><CheckCircle2 size={16} aria-hidden="true" />{saving ? "Сохраняем…" : "Сохранить исключение"}</Button></div>
        </form>
        <div className="mt-6 overflow-x-auto rounded-md border border-amber-400/20">
          <table className="min-w-[840px] w-full text-left text-sm"><thead className="border-b border-amber-400/15 text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-3 py-3">Группа</th><th className="px-3 py-3">Правило</th><th className="px-3 py-3">Причина</th><th className="px-3 py-3">До</th><th className="px-3 py-3"><span className="sr-only">Действия</span></th></tr></thead><tbody>{(settings?.exceptions ?? []).length ? (settings?.exceptions ?? []).map((item) => <tr key={item.id} className="border-b border-slate-800/80 align-top last:border-0"><td className="px-3 py-3 font-semibold text-slate-100">{item.groupName}</td><td className="px-3 py-3 break-all text-slate-300">{item.ruleId}</td><td className="max-w-md px-3 py-3 leading-6 text-slate-400">{item.reason}</td><td className={`px-3 py-3 ${item.active ? "text-amber-100" : "text-slate-500"}`}>{dateTimeValue(item.expiresAt)}{item.active ? "" : " · истекло"}</td><td className="px-3 py-3 text-right"><Button type="button" variant="danger" className="h-8 px-3 text-xs" disabled={saving} onClick={() => void remove({ kind: "exception", id: item.id })}><Trash2 size={14} aria-hidden="true" />Удалить</Button></td></tr>) : <tr><td colSpan={5} className="px-3 py-5 text-slate-500">Согласованных исключений нет.</td></tr>}</tbody></table>
        </div>
      </section>

      {message ? <p role="status" className="rounded-md border border-sky-400/25 bg-sky-500/10 px-3 py-2 text-sm text-sky-100">{message}</p> : null}
    </div>
  );
}
