"use client";

import { Select } from "@/components/ui/select";

import { CheckCircle2, Download, FileCode2, Play, Plus, RefreshCw, Save, ShieldAlert, Trash2 } from "lucide-react";
import { useDeferredValue, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { AuditJobHistory, useAuditJobs } from "@/components/hosts/audit-jobs-provider";
import { useActionResult, useNotify } from "@/components/ui/feedback";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button } from "@/components/ui/button";
import type { CustomPlaybookMode, PlaybookValidation } from "@/lib/playbook-registry";
import { playbookYamlIssue } from "@/lib/playbook-yaml";

type Variable = {
  name: string;
  label: string;
  type: "string" | "number";
  required: boolean;
  defaultValue?: string;
  placeholder?: string;
};

type RegisteredPlaybook = {
  id: string;
  title: string;
  file: string;
  kind: "audit" | "response";
  source: "builtin" | "custom";
  requiresLimit: boolean;
  variables: Variable[];
  requiresConfirmation?: boolean;
  requiresTargetSudo?: boolean;
};

type Template = {
  id: string;
  title: string;
  description: string;
  kind: "audit" | "response";
  variables: Variable[];
};

type CustomPlaybookCapabilities = {
  authoringEnabled: boolean;
  executionEnabled: boolean;
  productionLocked: boolean;
  reason: string;
};

export function PlaybooksClient() {
  const [playbooks, setPlaybooks] = useState<RegisteredPlaybook[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [selected, setSelected] = useState<RegisteredPlaybook | null>(null);
  const [content, setContent] = useState("");
  const [title, setTitle] = useState("");
  const [kind, setKind] = useState<"audit" | "response">("audit");
  const [requiresLimit, setRequiresLimit] = useState(false);
  const [variablesJson, setVariablesJson] = useState("[]");
  const [limit, setLimit] = useState("");
  const [hosts, setHosts] = useState<{alias: string; address: string; sudoMode?: string}[]>([]);
  const [sudoPassword, setSudoPassword] = useState("");
  const [confirmAudit, setConfirmAudit] = useState(false);
  const [profileId, setProfileId] = useState("basic_linux");
  const [nmapScope, setNmapScope] = useState("top_100");
  const [savedSignature, setSavedSignature] = useState("");
  const [validation, setValidation] = useState<PlaybookValidation>({});
  const [executionMode, setExecutionMode] = useState<CustomPlaybookMode>("draft");
  const openSequence = useRef(0);
  const yamlEditor = useRef<HTMLTextAreaElement>(null);
  const {jobs, rememberJob} = useAuditJobs();
  const [runVariables, setRunVariables] = useState<Record<string, string>>({});
  const [newId, setNewId] = useState("");
  const [newTitle, setNewTitle] = useState("");
  const [templateId, setTemplateId] = useState("audit-package");
  const [customPlaybooks, setCustomPlaybooks] = useState<CustomPlaybookCapabilities>({
    authoringEnabled: false,
    executionEnabled: false,
    productionLocked: false,
    reason: "Загружаем состояние пользовательских сценариев.",
  });
  const [loading, setLoading] = useState("");
  const [result, setResult] = useActionResult<{ ok?: boolean; message?: string; stdout?: string; stderr?: string; command?: string }>();
  const notify = useNotify();
  const selectedHost = hosts.find((host) => host.alias === limit);
  const customSelected = selected?.source === "custom";
  const managedPackage = customSelected && executionMode === "package";
  const requiresSudo = !managedPackage && selectedHost?.sudoMode === "on_demand" && selected?.requiresTargetSudo !== false;
  const dirty = selected?.source === "custom" && savedSignature !== JSON.stringify([content, title, kind, requiresLimit, variablesJson]);
  const activeJob = jobs.some((job) => job.hostAlias === limit && ["queued", "running"].includes(job.status));
  const deferredContent = useDeferredValue(content);
  const yamlIssue = useMemo(() => customSelected ? playbookYamlIssue(deferredContent) : null, [customSelected, deferredContent]);
  const syntaxPassed = Boolean(!dirty && validation.syntaxAt);
  const trial = dirty ? undefined : validation.trial;
  const customRunLocked = customSelected && executionMode === "draft";
  const runBlockedReason = getRunBlockedReason();

  const template = useMemo(
    () => templates.find((item) => item.id === templateId),
    [templates, templateId],
  );
  useEffect(() => {
    void loadPlaybooks();
    let ignore = false;
    void fetch("/api/ansible/hosts").then(readApiResponse).then((payload) => {
      if (ignore) return;
      if (!payload.ok) throw new Error(payload.message || "Не удалось загрузить хосты.");
      const available = (payload.hosts ?? []).filter((host: {groups: string[]}) => host.groups.includes("linux_hosts"));
      setHosts(available);
      setLimit((current) => available.some((host: {alias: string}) => host.alias === current) ? current : available[0]?.alias ?? "");
    }).catch((error) => { if (!ignore) setResult({ok: false, message: errorMessage(error, "Не удалось загрузить хосты.")}); });
    return () => { ignore = true; openSequence.current++; };
  }, []);

  useEffect(() => { setSudoPassword(""); setConfirmAudit(false); }, [selectedId, limit]);

  useEffect(() => {
    if (!selectedId && playbooks[0]) {
      setSelectedId(playbooks[0].id);
    }
  }, [playbooks, selectedId]);

  useEffect(() => {
    if (selectedId) {
      void openPlaybook(selectedId);
    }
  }, [selectedId]);

  async function loadPlaybooks(announce = false) {
    setLoading("load");
    try {
      const response = await fetch("/api/ansible/playbooks");
      const payload = await readApiResponse(response);
      if (!response.ok || !payload.ok) throw new Error(payload.message || "Не удалось загрузить сценарии.");
      setPlaybooks(payload.playbooks ?? []);
      if (announce) notify("Список сценариев обновлён.", "success");
      setTemplates(payload.templates ?? []);
      setCustomPlaybooks(payload.customPlaybooks ?? {
        authoringEnabled: Boolean(payload.customPlaybooksEnabled),
        executionEnabled: Boolean(payload.customPlaybooksEnabled),
        productionLocked: false,
        reason: Boolean(payload.customPlaybooksEnabled)
          ? "Пользовательские сценарии доступны."
          : "Пользовательские сценарии выключены.",
      });
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  async function openPlaybook(id: string) {
    const sequence = ++openSequence.current;
    setLoading("open");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(id)}`);
      const payload = await readApiResponse(response);
      if (sequence !== openSequence.current) return;
      if (!payload.ok) {
        setResult(payload);
        return;
      }
      const playbook = payload.playbook as RegisteredPlaybook;
      setSelected(playbook);
      setExecutionMode(payload.executionMode ?? "draft");
      setValidation(payload.validation ?? {});
      setContent(payload.content ?? "");
      setTitle(playbook.title);
      setKind(playbook.kind);
      setRequiresLimit(playbook.requiresLimit);
      setVariablesJson(JSON.stringify(playbook.variables ?? [], null, 2));
      setSavedSignature(JSON.stringify([payload.content ?? "", playbook.title, playbook.kind, playbook.requiresLimit, JSON.stringify(playbook.variables ?? [], null, 2)]));
      setRunVariables(Object.fromEntries((playbook.variables ?? []).map((variable) => [variable.name, variable.defaultValue ?? ""])));
    } catch (error) {
      if (sequence === openSequence.current) setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      if (sequence === openSequence.current) setLoading("");
    }
  }

  async function createPlaybook() {
    setLoading("create");
    setResult(null);
    try {
      const response = await fetch("/api/ansible/playbooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: newId, title: newTitle, templateId }),
      });
      const payload = await readApiResponse(response);
      setResult(payload);
      if (payload.ok) {
        setNewId("");
        setNewTitle("");
        await loadPlaybooks();
        setSelectedId(payload.playbook.id);
      }
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  async function savePlaybook() {
    if (!selected || selected.id !== selectedId) {
      return;
    }

    let variables: Variable[];
    try {
      variables = JSON.parse(variablesJson) as Variable[];
      if (!Array.isArray(variables)) {
        throw new Error();
      }
    } catch {
      setResult({ ok: false, message: "Variables должны быть валидным JSON-массивом." });
      return;
    }

    setLoading("save");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(selected.id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, kind, requiresLimit, variables, content }),
      });
      const payload = await readApiResponse(response);
      setResult(payload);
      if (payload.ok) {
        await loadPlaybooks();
        await openPlaybook(selected.id);
      }
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  async function deletePlaybook() {
    if (!selected || selected.id !== selectedId || !window.confirm(`Удалить ${selected.title}?`)) {
      return;
    }

    setLoading("delete");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(selected.id)}`, { method: "DELETE" });
      const payload = await readApiResponse(response);
      setResult(payload);
      if (payload.ok) {
        setSelectedId("");
        setSelected(null);
        setContent("");
        await loadPlaybooks();
      }
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  async function syntaxCheck() {
    if (!selected || selected.id !== selectedId || dirty) {
      return;
    }
    setLoading("syntax");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(selected.id)}/syntax`, { method: "POST" });
      const payload = await readApiResponse(response);
      if (payload.ok && selected.source === "custom") {
        setResult({ ...payload, message: "Ansible проверил синтаксис сохранённого сценария." });
        updateValidation(payload.validation);
      } else {
        setResult(payload);
      }
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  function getRunBlockedReason() {
    if (customRunLocked) return "Этот YAML запускается в тестовом экземпляре. Здесь доступен запуск сценариев из шаблона «Проверить пакет».";
    if (loading === "run") return "Подготавливаем запуск…";
    if (loading || selected?.id !== selectedId) return "Дождитесь загрузки сценария.";
    if (!selectedHost) return "Выберите подключённый Linux-хост.";
    if (activeJob) return "На выбранном хосте уже выполняется проверка.";
    if (dirty) return "Сохраните черновик перед запуском.";
    if (managedPackage && !runVariables.package_name?.trim()) return "Укажите имя пакета.";
    if (customSelected && !managedPackage && !syntaxPassed) return "Проверьте YAML перед пробным запуском.";
    if (requiresSudo && !sudoPassword) return "Введите пароль sudo для этого запуска.";
    if (selected?.requiresConfirmation && !confirmAudit) return "Подтвердите запуск на выбранном хосте.";
    return "";
  }

  async function runPlaybook() {
    if (!selected || runBlockedReason) return;
    if (sudoPassword && window.location.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname)) {
      setResult({ok: false, message: "Для пароля sudo используйте HTTPS либо localhost."}); return;
    }
    if (selected.kind === "response" && !window.confirm("Запустить response-playbook? Он может изменить выбранные хосты.")) {
      return;
    }
    setLoading("run");
    setResult(null);
    try {
      const builtin = selected.source === "builtin";
      let confirmRepeatAudit = false;
      if (builtin) {
        const params = new URLSearchParams({action: selected.id, profileId, limit});
        if (selected.id === "networkPortScan") params.set("nmapScanScope", nmapScope);
        const response = await fetch(`/api/ansible/audit-repeat?${params}`);
        const payload = await readApiResponse(response);
        if (!response.ok || !payload.ok) throw new Error(payload.message || "Не удалось проверить историю запусков.");
        if (payload.repeatAudit) {
          if (!window.confirm(`${payload.repeatAudit.message}\n\nЗапустить проверку повторно?`)) {
            setResult({ok: true, message: "Повторный запуск отменён. Существующий отчёт доступен в истории проверок."});
            return;
          }
          confirmRepeatAudit = true;
        }
      }
      if (requiresSudo) setSudoPassword("");
      const response = await fetch(builtin ? "/api/ansible/jobs" : `/api/ansible/playbooks/${encodeURIComponent(selected.id)}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit, ...(requiresSudo ? {sudoPassword} : {}), ...(builtin
          ? {action: selected.id, profileId, confirmAudit, confirmRepeatAudit, extraVars: selected.id === "networkPortScan" ? {nmap_scan_scope: nmapScope} : {}}
          : {variables: runVariables}) }),
      });
      const payload = await readApiResponse(response);
      if (payload.ok && payload.job) { rememberJob(payload.job); setResult({ok: true, message: "Проверка запущена на сервере. Её состояние и отчёт появятся в истории проверок."}); }
      else {
        setResult(payload);
        if (!builtin && payload.ok) updateValidation(payload.validation);
      }
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  function updateValidation(current?: PlaybookValidation) {
    if (current?.revision === validation.revision) {
      setValidation(current ?? {});
    } else {
      setValidation({});
      setResult({ ok: false, message: "Версия черновика изменилась. Обновите страницу." });
    }
  }

  function goToYamlIssue() {
    const editor = yamlEditor.current;
    if (!editor || !yamlIssue?.line) return;
    const lines = content.split("\n");
    const start = lines.slice(0, yamlIssue.line - 1).reduce((offset, line) => offset + line.length + 1, 0);
    const caret = start + (yamlIssue.col ?? 1) - 1;
    // Measure wrapped rows with the same font, width and padding as the editor.
    const measure = editor.cloneNode() as HTMLTextAreaElement;
    measure.removeAttribute("aria-label");
    measure.value = content.slice(0, caret) + " ";
    Object.assign(measure.style, {
      position: "fixed", visibility: "hidden", width: `${editor.getBoundingClientRect().width}px`,
      height: "0", minHeight: "0",
    });
    editor.after(measure);
    const { lineHeight, paddingTop, paddingBottom } = getComputedStyle(measure);
    const scrollTop = measure.scrollHeight - parseFloat(paddingTop) - parseFloat(paddingBottom) - 3 * parseFloat(lineHeight);
    measure.remove();
    editor.focus();
    editor.setSelectionRange(caret, caret);
    editor.scrollTop = Math.max(0, scrollTop);
  }

  function keepPagePositionOnEnter(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== "Enter" || event.nativeEvent.isComposing || event.currentTarget.readOnly) return;
    const left = window.scrollX;
    const top = window.scrollY;
    // Keep the browser's newline, caret movement and undo inside the editor.
    requestAnimationFrame(() => {
      if (left !== window.scrollX || top !== window.scrollY) window.scrollTo({ left, top, behavior: "instant" });
    });
  }

  function downloadYaml() {
    if (!selected || dirty) return;
    const url = URL.createObjectURL(new Blob([content], { type: "application/yaml" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${selected.id}.yml`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight text-white">Сценарии проверок</h1>
          <p className="mt-1 text-sm text-slate-400">Запускайте готовые проверки Ansible на выбранном хосте и готовьте свои черновики.</p>
        </div>
        <Button variant="secondary" onClick={() => loadPlaybooks(true)} disabled={Boolean(loading)}>
          <RefreshCw size={16} className={loading === "load" ? "animate-spin" : ""} aria-hidden="true" />
          Обновить список
        </Button>
      </header>

      <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="min-w-0 space-y-4">
        <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
          <div className="flex items-center justify-between border-b border-slate-800 p-4">
            <h2 id="playbook-list-heading" className="text-lg font-semibold text-white">1. Выберите сценарий</h2>
          </div>
          <div
            role="region"
            aria-labelledby="playbook-list-heading"
            tabIndex={0}
            className="max-h-[32.5rem] divide-y divide-slate-800 overflow-x-hidden overflow-y-auto [color-scheme:dark] [scrollbar-color:#64748b_#0f172a] [scrollbar-width:thin] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-sky-300 xl:max-h-[clamp(12rem,calc(100dvh-13rem),32.5rem)]"
          >
            {playbooks.map((playbook) => (
              <button
                key={playbook.id}
                onClick={() => setSelectedId(playbook.id)}
                disabled={Boolean(loading)}
                aria-pressed={selected?.id === playbook.id}
                className={`block w-full p-3 text-left text-sm transition hover:bg-slate-900 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-sky-300 ${
                  selected?.id === playbook.id ? "bg-sky-500/10" : ""
                }`}
              >
                <span className="block font-semibold text-white">{playbook.title}</span>
                <span className="mt-1 block text-xs text-slate-500">{playbook.kind === "audit" ? "Проверка" : "Изменение"} · {playbook.source === "builtin" ? "Встроенный" : "Собственный"}</span>
              </button>
            ))}
          </div>
        </section>

        <details className="rounded-md border border-slate-800 bg-slate-950/70 p-3 text-xs text-slate-400">
          <summary className="cursor-pointer font-semibold text-sky-200">Собственные сценарии</summary>
          <p className="mt-2 leading-5">{customPlaybooks.reason}</p>
          {!customPlaybooks.authoringEnabled ? <p className="mt-2 leading-5">Черновики включает администратор: <code>HCP_ENABLE_CUSTOM_AUDITS=true</code>. Произвольный YAML выполняется только в отдельном тестовом контуре.</p> : null}
        </details>

        {customPlaybooks.authoringEnabled ? <details className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
          <summary className="cursor-pointer font-semibold text-white">Создать черновик</summary>
          <div className="mt-4 space-y-3">
            <Field label="ID файла" value={newId} onChange={setNewId} placeholder="package-check" disabled={loading === "create"} />
            <Field label="Название" value={newTitle} onChange={setNewTitle} placeholder={template?.title} disabled={loading === "create"} />
            <div>
              <p className="text-xs font-semibold uppercase text-slate-500">Шаблон</p>
              <div className="mt-2 space-y-2">
                {templates.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setTemplateId(item.id)}
                    className={`w-full rounded-md border p-3 text-left text-sm transition ${
                      templateId === item.id
                        ? "border-sky-300 bg-sky-500/10"
                        : "border-slate-800 bg-slate-900/70 hover:border-slate-600"
                    }`}
                  >
                    <span className="flex items-center justify-between gap-3">
                      <span className="font-semibold text-white">{item.title}</span>
                      <span className={item.kind === "response" ? "text-red-200" : "text-emerald-200"}>{item.kind === "audit" ? "Проверка" : "Изменение"}</span>
                    </span>
                    <span className="mt-1 block text-xs leading-5 text-slate-400">{item.description}</span>
                    <span className="mt-2 block text-xs text-slate-500">
                      Поля запуска: {item.variables.map((variable) => `${variable.label} (${variable.name})`).join(", ") || "нет"}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            <Button onClick={createPlaybook} disabled={Boolean(loading) || !newId.trim()} className="w-full">
              <Plus size={16} aria-hidden="true" />
              Создать
            </Button>
          </div>
        </details> : null}
      </aside>

      <div className="min-w-0 space-y-4">
        {selected ? (
          <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  {selected.kind === "response" ? (
                    <ShieldAlert className="text-red-200" size={20} aria-hidden="true" />
                  ) : (
                    <FileCode2 className="text-sky-200" size={20} aria-hidden="true" />
                  )}
                  <h2 className="text-lg font-semibold text-white">{selected.title}</h2>
                </div>
              </div>

            </div>

            <h3 className="mt-4 font-semibold text-white">2. Параметры запуска</h3>
            <div className="mt-3 max-w-md">
              <label className="block"><span className="text-xs font-semibold uppercase text-slate-500">Целевой хост</span>
                <Select aria-label="Целевой хост" value={limit} onValueChange={setLimit} className="mt-2 w-full">
                  {hosts.length ? hosts.map((host) => <option key={host.alias} value={host.alias}>{host.alias} · {host.address}</option>) : <option value="">Нет подключённых хостов</option>}
                </Select>
              </label>
            </div>
            {dirty ? <p className="mt-3 text-sm text-amber-200">Сохраните черновик перед проверкой и запуском.</p> : null}
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {selected.id === "agentlessAudit" ? <label><span className="text-xs font-semibold text-slate-400">Профиль аудита</span><Select aria-label="Профиль аудита" className="mt-2 w-full" value={profileId} onValueChange={setProfileId}><option value="basic_linux">Базовый Linux</option><option value="ssh_security">SSH-сервер</option><option value="web_server">Веб-сервер</option><option value="docker_host">Docker-хост</option></Select></label> : null}
              {selected.id === "networkPortScan" ? <label><span className="text-xs font-semibold text-slate-400">Глубина сканирования</span><Select aria-label="Глубина сканирования" className="mt-2 w-full" value={nmapScope} onValueChange={setNmapScope}><option value="top_100">100 популярных портов</option><option value="top_1000">1000 популярных портов</option><option value="full_tcp">Все TCP-порты</option></Select></label> : null}
            </div>

            {selected.variables.length ? (
              <div className="mt-4 grid gap-3 md:grid-cols-3">
                {selected.variables.map((variable) => (
                  <Field
                    key={variable.name}
                    label={variable.label}
                    value={runVariables[variable.name] ?? ""}
                    placeholder={variable.placeholder}
                    onChange={(value) => setRunVariables((current) => ({ ...current, [variable.name]: value }))}
                  />
                ))}
              </div>
            ) : null}

<details open={selected.source === "custom"} className="mt-4 rounded-lg border border-slate-800 p-3"><summary className="cursor-pointer text-sm text-sky-200">{selected.source === "custom" ? "YAML и параметры черновика" : "Посмотреть YAML"}</summary>
<p className="mt-2 break-all text-xs text-slate-500">{selected.file}</p>
{selected.source === "custom" ? <div className="mt-3"><Field label="Название" value={title} onChange={setTitle} /></div> : null}
            <div className="mt-4 space-y-3">
              <div className="block">
                <span className="flex items-center justify-between gap-3 text-xs font-semibold uppercase text-slate-500">
                  <span>YAML</span>
                  <span className={selected.source === "custom" ? "text-emerald-200" : "text-slate-500"}>
                    {selected.source === "custom" ? "можно редактировать" : "только просмотр"}
                  </span>
                </span>
                  <textarea
                    ref={yamlEditor}
                    aria-label="YAML сценария"
                    aria-describedby={customSelected ? "playbook-yaml-feedback" : undefined}
                    aria-invalid={yamlIssue?.line ? true : undefined}
                    value={content}
                    onChange={(event) => setContent(event.target.value)}
                    onKeyDown={keepPagePositionOnEnter}
                    readOnly={selected.source !== "custom"}
                    spellCheck={false}
                    wrap="soft"
                    className="mt-2 block h-[clamp(14rem,48dvh,30rem)] max-h-[75dvh] w-full resize-y overflow-x-hidden overflow-y-auto overscroll-y-contain border border-slate-700 p-4 font-mono text-sm leading-5 [overflow-wrap:anywhere] [scrollbar-gutter:stable] read-only:opacity-75"
                  />
                {customSelected ? <div id="playbook-yaml-feedback" className={`mt-2 flex flex-wrap items-center gap-x-2 text-xs ${yamlIssue ? "text-amber-200" : "text-slate-400"}`}>
                  {yamlIssue?.line ? <button type="button" onClick={goToYamlIssue} className="font-semibold underline underline-offset-2">
                    Строка {yamlIssue.line}{yamlIssue.col ? `, столбец ${yamlIssue.col}` : ""}
                  </button> : null}
                  <span>{yamlIssue?.message ?? "Структура YAML разобрана."}</span>
                </div> : null}
              </div>
              {customSelected && <details className="rounded-md border border-slate-800 p-3">
                <summary className="cursor-pointer text-xs font-semibold text-sky-200">Переменные (JSON)</summary>
                <textarea
                  aria-label="Переменные (JSON)"
                  value={variablesJson}
                  onChange={(event) => setVariablesJson(event.target.value)}
                  spellCheck={false}
                  onKeyDown={keepPagePositionOnEnter}
                  className="mt-2 block h-44 w-full resize-y overscroll-y-contain border border-slate-700 p-4 font-mono text-xs leading-5"
                />

              </details>}
            </div>
              <div className="mt-4 flex flex-wrap gap-3">
                {selected.source === "custom" ? (
                    <Button variant="secondary" onClick={savePlaybook} disabled={Boolean(loading) || !dirty}>
                      <Save size={16} className={loading === "save" ? "animate-spin" : ""} aria-hidden="true" />
                      Сохранить
                    </Button>
                ) : null}
                {customSelected ? <Button variant="secondary" onClick={downloadYaml} disabled={Boolean(loading) || dirty}>
                  <Download size={16} aria-hidden="true" /> Скачать YAML
                </Button> : null}

                {!customRunLocked && <Button
                  variant="secondary"
                  onClick={syntaxCheck}
                  disabled={Boolean(loading) || dirty}
                >
                  <CheckCircle2 size={16} className={loading === "syntax" ? "animate-spin" : ""} aria-hidden="true" />
                  Проверить YAML
                </Button>}
                {selected.source === "custom" ? <Button variant="danger" onClick={deletePlaybook} disabled={Boolean(loading)}>
                      <Trash2 size={16} aria-hidden="true" />
                      Удалить черновик
                    </Button> : null}
              </div>
</details>
            <div id="playbook-run-actions" className="mt-4 border-t border-slate-800 pt-4">
                {customSelected ? <div role="status" className="mb-3 flex flex-wrap gap-2 text-xs">
                  <span className={`rounded-md border px-2.5 py-1.5 ${syntaxPassed ? "border-emerald-500/40 text-emerald-200" : "border-slate-700 text-slate-400"}`}>
                    {syntaxPassed ? "Синтаксис проверен" : "Синтаксис не проверен"}
                  </span>
                  <span title={trial ? new Date(trial.at).toLocaleString("ru-RU") : undefined} className={`rounded-md border px-2.5 py-1.5 ${trial ? "border-emerald-500/40 text-emerald-200" : "border-slate-700 text-slate-400"}`}>
                    {trial ? `Последний успешный запуск · ${trial.host}` : "Успешных запусков нет"}
                  </span>
                </div> : null}
                {requiresSudo && !customRunLocked ? <div className="mb-3 max-w-md">
                  <Field label="Пароль sudo для одного запуска" value={sudoPassword} onChange={setSudoPassword} type="password" disabled={loading === "run"} />
                  <p className="mt-1 text-xs text-slate-400">Для повторного запуска введите пароль заново.</p>
                </div> : null}
                {selected.requiresConfirmation ? <label className="mb-3 flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={confirmAudit} onChange={(event) => setConfirmAudit(event.target.checked)} />Подтверждаю запуск на выбранном хосте</label> : null}
                <div className="flex flex-wrap items-center gap-3">
                  {!customRunLocked && <Button
                    variant={selected.kind === "response" ? "danger" : "primary"}
                    onClick={runPlaybook}
                    disabled={Boolean(runBlockedReason)}
                    aria-describedby={runBlockedReason ? "playbook-run-status" : undefined}
                  >
                    <Play size={16} className={loading === "run" ? "animate-spin" : ""} aria-hidden="true" />
                    {customSelected && !managedPackage ? "Пробный запуск" : "Запустить"}
                  </Button>}
                  <p id="playbook-run-status" role="status" className="text-sm text-slate-300">{runBlockedReason || (managedPackage ? "Проверка пакета без sudo." : "")}</p>
                </div>
            </div>
          </section>
        ) : null}

        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="text-lg font-semibold text-white">3. Результат</h2>
          <AuditJobHistory hostAlias={limit} />
          {result ? (
            <div className="mt-3 space-y-3 text-sm">
              <div className={`rounded-md border p-3 ${
                result.ok ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100" : "border-red-400/30 bg-red-500/10 text-red-100"
              }`}>
                <p className="font-semibold">{result.ok ? "OK" : "Ошибка"}</p>
                {result.message ? <p className="mt-1">{result.message}</p> : null}

              </div>
              <details><summary className="cursor-pointer text-xs text-sky-200">Технический вывод</summary>
              <pre className="mt-2 max-h-80 overflow-auto rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
{`${result.stdout ?? ""}${result.stderr ? `\n\nSTDERR:\n${result.stderr}` : ""}`}
              </pre></details>
            </div>
          ) : null}
        </section>
      </div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  disabled = false,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
  type?: "text" | "password";
}) {
  return (
    <label className="block">
      <span className="text-xs font-semibold uppercase text-slate-500">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        placeholder={placeholder}
        className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100 disabled:opacity-60"
      />
    </label>
  );
}
