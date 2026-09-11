"use client";

import { CheckCircle2, FileCode2, Play, Plus, RefreshCw, Save, ShieldAlert, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useActionResult, useNotify } from "@/components/ui/feedback";
import { readApiResponse, errorMessage } from "@/lib/client-api";
import { Button } from "@/components/ui/button";

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
};

type Template = {
  id: string;
  title: string;
  description: string;
  kind: "audit" | "response";
  variables: Variable[];
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
  const [limit, setLimit] = useState("linux_hosts");
  const [runVariables, setRunVariables] = useState<Record<string, string>>({});
  const [newId, setNewId] = useState("fix-cve");
  const [newTitle, setNewTitle] = useState("Fix CVE");
  const [templateId, setTemplateId] = useState("audit-package");
  const [customPlaybooksEnabled, setCustomPlaybooksEnabled] = useState(false);
  const [loading, setLoading] = useState("");
  const [result, setResult] = useActionResult<{ ok?: boolean; message?: string; stdout?: string; stderr?: string; command?: string }>();
  const notify = useNotify();

  const template = useMemo(
    () => templates.find((item) => item.id === templateId),
    [templates, templateId],
  );
  const yamlLineNumbers = useMemo(
    () => content.split("\n").map((_, index) => index + 1).join("\n"),
    [content],
  );

  useEffect(() => {
    void loadPlaybooks();
  }, []);

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
      setCustomPlaybooksEnabled(Boolean(payload.customPlaybooksEnabled));
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  async function openPlaybook(id: string) {
    setLoading("open");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(id)}`);
      const payload = await readApiResponse(response);
      if (!payload.ok) {
        setResult(payload);
        return;
      }
      const playbook = payload.playbook as RegisteredPlaybook;
      setSelected(playbook);
      setContent(payload.content ?? "");
      setTitle(playbook.title);
      setKind(playbook.kind);
      setRequiresLimit(playbook.requiresLimit);
      setVariablesJson(JSON.stringify(playbook.variables ?? [], null, 2));
      setRunVariables(Object.fromEntries((playbook.variables ?? []).map((variable) => [variable.name, variable.defaultValue ?? ""])));
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
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
    if (!selected) {
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
    if (!selected || !window.confirm(`Удалить ${selected.title}?`)) {
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
    if (!selected) {
      return;
    }
    setLoading("syntax");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(selected.id)}/syntax`, { method: "POST" });
      setResult(await readApiResponse(response));
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  async function runPlaybook() {
    if (!selected) {
      return;
    }
    if (selected.kind === "response" && !window.confirm("Запустить response-playbook? Он может изменить выбранные хосты.")) {
      return;
    }
    setLoading("run");
    setResult(null);
    try {
      const response = await fetch(`/api/ansible/playbooks/${encodeURIComponent(selected.id)}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit, variables: runVariables }),
      });
      setResult(await readApiResponse(response));
    } catch (error) {
      setResult({ ok: false, message: errorMessage(error, "Ответ не получен. Проверьте журнал действий перед повторным запуском.") });
    } finally {
      setLoading("");
    }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="space-y-4">
        <section className="overflow-hidden rounded-md border border-slate-800 bg-slate-950/70">
          <div className="flex items-center justify-between border-b border-slate-800 p-4">
            <h1 className="text-lg font-semibold text-white">Playbook'и</h1>
            <Button variant="secondary" onClick={() => loadPlaybooks(true)} disabled={Boolean(loading)}>
              <RefreshCw size={16} className={loading === "load" ? "animate-spin" : ""} aria-hidden="true" />
            </Button>
          </div>
          <div className="max-h-[520px] divide-y divide-slate-800 overflow-auto">
            {playbooks.map((playbook) => (
              <button
                key={playbook.id}
                onClick={() => setSelectedId(playbook.id)}
                className={`block w-full p-3 text-left text-sm transition hover:bg-slate-900 ${
                  selected?.id === playbook.id ? "bg-sky-500/10" : ""
                }`}
              >
                <span className="block font-semibold text-white">{playbook.title}</span>
                <span className="mt-1 block text-xs text-slate-500">{playbook.kind} · {playbook.source}</span>
              </button>
            ))}
          </div>
        </section>

        {customPlaybooksEnabled ? <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="text-lg font-semibold text-white">Создать playbook</h2>
          <div className="mt-4 space-y-3">
            <Field label="ID файла" value={newId} onChange={setNewId} />
            <Field label="Название" value={newTitle} onChange={setNewTitle} />
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
                      <span className={item.kind === "response" ? "text-red-200" : "text-emerald-200"}>{item.kind}</span>
                    </span>
                    <span className="mt-1 block text-xs leading-5 text-slate-400">{item.description}</span>
                    <span className="mt-2 block text-xs text-slate-500">
                      Поля запуска: {item.variables.map((variable) => `${variable.label} (${variable.name})`).join(", ") || "нет"}
                    </span>
                  </button>
                ))}
              </div>
            </div>
            {template ? (
              <div className="rounded-md border border-slate-800 bg-slate-900/70 p-3 text-xs leading-5 text-slate-400">
                <p className="font-semibold text-slate-200">Что будет создано</p>
                <p className="mt-1">YAML в `ansible/playbooks/custom/{newId || "id"}.yml` и meta-файл рядом.</p>
              </div>
            ) : null}
            <Button onClick={createPlaybook} disabled={Boolean(loading)} className="w-full">
              <Plus size={16} aria-hidden="true" />
              Создать
            </Button>
          </div>
        </section> : null}
      </aside>

      <main className="space-y-4">
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
                <p className="mt-1 text-xs text-slate-500">{selected.file}</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="secondary" onClick={syntaxCheck} disabled={Boolean(loading)}>
                  <CheckCircle2 size={16} className={loading === "syntax" ? "animate-spin" : ""} aria-hidden="true" />
                  Syntax
                </Button>
                <Button variant={selected.kind === "response" ? "danger" : "primary"} onClick={runPlaybook} disabled={Boolean(loading)}>
                  <Play size={16} className={loading === "run" ? "animate-spin" : ""} aria-hidden="true" />
                  Run
                </Button>
                {selected.source === "custom" ? (
                  <>
                    <Button variant="secondary" onClick={savePlaybook} disabled={Boolean(loading)}>
                      <Save size={16} className={loading === "save" ? "animate-spin" : ""} aria-hidden="true" />
                      Save
                    </Button>
                    <Button variant="danger" onClick={deletePlaybook} disabled={Boolean(loading)}>
                      <Trash2 size={16} aria-hidden="true" />
                      Delete
                    </Button>
                  </>
                ) : null}
              </div>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-4">
              <Field label="Название" value={title} onChange={setTitle} disabled={selected.source !== "custom"} />
              <label className="block">
                <span className="text-xs font-semibold uppercase text-slate-500">Тип</span>
                <select
                  value={kind}
                  onChange={(event) => setKind(event.target.value === "audit" ? "audit" : "response")}
                  disabled={selected.source !== "custom"}
                  className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100 disabled:opacity-60"
                >
                  <option value="audit">audit</option>
                  <option value="response">response</option>
                </select>
              </label>
              <label className="flex h-10 items-center gap-2 self-end rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-200">
                <input
                  type="checkbox"
                  checked={requiresLimit}
                  onChange={(event) => setRequiresLimit(event.target.checked)}
                  disabled={selected.source !== "custom"}
                  className="h-4 w-4 rounded border-slate-600 bg-slate-950"
                />
                requires limit
              </label>
              <Field label="Run limit" value={limit} onChange={setLimit} />
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

            <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
              <label className="block">
                <span className="flex items-center justify-between gap-3 text-xs font-semibold uppercase text-slate-500">
                  <span>YAML</span>
                  <span className={selected.source === "custom" ? "text-emerald-200" : "text-slate-500"}>
                    {selected.source === "custom" ? "можно редактировать" : "только просмотр"}
                  </span>
                </span>
                <div className="mt-2 grid h-[560px] grid-cols-[48px_minmax(0,1fr)] overflow-hidden rounded-md border border-slate-700 bg-slate-950">
                  <pre className="overflow-hidden border-r border-slate-800 bg-slate-900/80 px-3 py-4 text-right font-mono text-xs leading-5 text-slate-600">
                    {yamlLineNumbers}
                  </pre>
                  <textarea
                    value={content}
                    onChange={(event) => setContent(event.target.value)}
                    readOnly={selected.source !== "custom"}
                    spellCheck={false}
                    className="h-full w-full resize-none bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100 outline-none read-only:opacity-75"
                  />
                </div>
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase text-slate-500">Variables JSON</span>
                <textarea
                  value={variablesJson}
                  onChange={(event) => setVariablesJson(event.target.value)}
                  readOnly={selected.source !== "custom"}
                  spellCheck={false}
                  className="mt-2 h-[220px] w-full resize-y rounded-md border border-slate-700 bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100 read-only:opacity-75"
                />
                <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/70 p-3 text-xs leading-5 text-slate-400">
                  <p className="font-semibold text-slate-200">Что такое “Имя пакета”</p>
                  <p className="mt-1">Это системный пакет Linux, например `openssl`, `nginx`, `curl` или `openssh-server`.</p>
                  <p className="mt-3 font-semibold text-slate-200">Где менять шаблон</p>
                  <p className="mt-1">После создания редактируйте YAML здесь или файл в `ansible/playbooks/custom`.</p>
                  <p className="mt-2">Встроенные playbook'и read-only. Для своей логики создайте custom.</p>
                </div>
              </label>
            </div>
          </section>
        ) : null}

        <section className="rounded-md border border-slate-800 bg-slate-950/70 p-4">
          <h2 className="text-lg font-semibold text-white">Результат</h2>
          {result ? (
            <div className="mt-3 space-y-3 text-sm">
              <div className={`rounded-md border p-3 ${
                result.ok ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100" : "border-red-400/30 bg-red-500/10 text-red-100"
              }`}>
                <p className="font-semibold">{result.ok ? "OK" : "Ошибка"}</p>
                {result.message ? <p className="mt-1">{result.message}</p> : null}
                {result.command ? <p className="mt-1 break-all text-xs">{result.command}</p> : null}
              </div>
              <pre className="max-h-80 overflow-auto rounded-md bg-slate-900 p-3 text-xs leading-5 text-slate-200">
{`${result.stdout ?? ""}${result.stderr ? `\n\nSTDERR:\n${result.stderr}` : ""}`}
              </pre>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-400">Откройте playbook, измените custom YAML, сохраните, проверьте syntax-check и запустите.</p>
          )}
        </section>
      </main>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  disabled = false,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
}) {
  return (
    <label className="block">
      <span className="text-xs font-semibold uppercase text-slate-500">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        placeholder={placeholder}
        className="mt-2 h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100 disabled:opacity-60"
      />
    </label>
  );
}
