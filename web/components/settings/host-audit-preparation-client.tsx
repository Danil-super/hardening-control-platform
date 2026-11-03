"use client";

import { useEffect, useState } from "react";
import { AlertCircle, FileCheck2, RefreshCw, Server } from "lucide-react";
import { Select } from "@/components/ui/select";
import { Button, LinkButton } from "@/components/ui/button";
import { readApiResponse, errorMessage } from "@/lib/client-api";

type Host = { alias: string };
type SourceState = {
  state: "configured" | "missing" | "conflict" | "incomplete";
  group: string | null;
  message: string;
  declaredRelease?: string | null;
  declaredArchitectures?: string[];
  mode?: "local" | "online" | null;
  sourceReviewRecorded?: boolean;
  profileKind?: "astra-hcp-18" | "custom" | "environment" | null;
};
type Preparation = {
  ok?: boolean;
  alias?: string;
  assessment?: string;
  astraOval?: SourceState;
  openScap?: SourceState;
  warning?: string;
  message?: string;
};
type HostsResponse = { ok?: boolean; hosts?: Host[]; message?: string };

const labels = {
  configured: "Настройка назначена",
  missing: "Не назначено",
  conflict: "Конфликт групп",
  incomplete: "Нужна корректировка",
} as const;

function SourceCard({
  title, source, href, linkText, description,
}: {
  title: string;
  source: SourceState;
  href: string;
  linkText: string;
  description: string;
}) {
  const isIssue = source.state === "conflict" || source.state === "incomplete";
  return (
    <article className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h3 className="font-semibold text-slate-100">{title}</h3>
        <span className={`text-xs font-semibold ${isIssue ? "text-red-200" :
          source.state === "missing" ? "text-amber-200" : "text-sky-200"}`}>
          {labels[source.state]}
        </span>
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-400">{description}</p>
      <p className="mt-3 text-sm leading-6 text-slate-200">{source.message}</p>
      {source.group ? <p className="mt-2 text-xs text-slate-400">Назначено через группу: <strong className="text-slate-200">{source.group}</strong></p> : null}
      {source.declaredRelease ? <p className="mt-1 text-xs text-slate-400">Указанная область выпуска: <strong className="text-slate-200">{source.declaredRelease}</strong> (не проверена на хосте)</p> : null}
      {source.declaredArchitectures?.length ? <p className="mt-1 text-xs text-slate-400">Указанные архитектуры: {source.declaredArchitectures.join(", ")}</p> : null}
      {source.mode ? <p className="mt-1 text-xs text-slate-400">Режим: {source.mode === "local" ? "локальный XML на цели" : "HTTPS через control node"}</p> : null}
      {source.sourceReviewRecorded ? <p className="mt-1 text-xs text-slate-400">В настройке сохранена отметка оператора о сверке источника. Это не доказательство цифровой подписи издателя.</p> : null}
      {source.profileKind ? <p className="mt-1 text-xs text-slate-400">Профиль: {source.profileKind === "astra-hcp-18" ? "встроенные 18 правил HCP" :
        source.profileKind === "environment" ? "задан в окружении" : "пользовательский"}</p> : null}
      <LinkButton href={href} variant="secondary" className="mt-4">
        {linkText}
      </LinkButton>
    </article>
  );
}

export function HostAuditPreparationClient() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [alias, setAlias] = useState("");
  const [hostsLoading, setHostsLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [preparation, setPreparation] = useState<Preparation | null>(null);
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch("/api/ansible/hosts", { cache: "no-store", signal: controller.signal });
        const payload = await readApiResponse(response) as HostsResponse;
        if (!response.ok || !payload.ok || !Array.isArray(payload.hosts)) {
          throw new Error(payload.message ?? "Не удалось прочитать inventory.");
        }
        const list = payload.hosts.filter(host => typeof host.alias === "string" && host.alias.length > 0);
        const requested = new URLSearchParams(window.location.search).get("host");
        if (!controller.signal.aborted) {
          setHosts(list);
          setAlias(current => list.some(host => host.alias === current) ? current
            : requested && list.some(host => host.alias === requested) ? requested : list[0]?.alias ?? "");
        }
      } catch (error) {
        if (!controller.signal.aborted) setLoadError(errorMessage(error, "Не удалось загрузить хосты."));
      } finally {
        if (!controller.signal.aborted) setHostsLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!alias || !hosts.some(host => host.alias === alias)) {
      setPreparation(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setPreparation(null);
    setLoadError("");
    async function load() {
      try {
        const response = await fetch(`/api/ansible/hosts/audit-preparation?alias=${encodeURIComponent(alias)}`,
          { cache: "no-store", signal: controller.signal });
        const payload = await readApiResponse(response) as Preparation;
        if (!response.ok || !payload.ok || payload.alias !== alias ||
          !payload.astraOval || !payload.openScap || payload.assessment !== "saved-settings-only") {
          throw new Error(payload.message ?? "Сведения об источниках неполные или относятся к другому хосту.");
        }
        if (!controller.signal.aborted) setPreparation(payload);
      } catch (error) {
        if (!controller.signal.aborted) setLoadError(errorMessage(error, "Не удалось оценить сохранённые назначения."));
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [alias, hosts, refresh]);

  return (
    <section id="host-audit-preparation" aria-labelledby="host-audit-preparation-title"
      className="scroll-mt-6 rounded-xl border border-sky-400/20 bg-slate-950/70 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-sky-200">Подготовка проверки</p>
          <h2 id="host-audit-preparation-title" className="mt-1 text-xl font-semibold text-white">Назначенные источники и политики по хосту</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Только чтение сохранённых настроек. HCP не связывается с целевым сервером и не скачивает базы
            при открытии этой секции. Назначение политики не подтверждает выполнение аудита.
          </p>
        </div>
        <Button variant="secondary" onClick={() => setRefresh(value => value + 1)}
          disabled={hostsLoading || loading || !alias}>
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} aria-hidden="true" />
          Обновить назначения
        </Button>
      </div>
      {hosts.length ? (
        <label className="mt-4 block max-w-sm">
          <span className="text-xs font-semibold text-slate-300">Подключённый хост</span>
          <Select value={alias} onValueChange={setAlias} disabled={hostsLoading}
            className="mt-2 h-10 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 text-sm text-slate-100">
            {hosts.map(host => <option key={host.alias} value={host.alias}>{host.alias}</option>)}
          </Select>
        </label>
      ) : null}
      {loadError ? <p role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">
        <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true"/>{loadError}
      </p> : null}
      {hostsLoading || loading ? <p role="status" className="mt-4 text-sm text-slate-400">Читаем сохранённые назначения. Сканирование не выполняется.</p> : null}
      {!hostsLoading && !hosts.length && !loadError ? (
        <div className="mt-4 flex items-start gap-3 text-sm text-slate-300">
          <Server size={20} className="shrink-0 text-sky-200" aria-hidden="true"/>
          <div>Сначала добавьте хост в inventory. <LinkButton href="/hosts" variant="secondary" className="mt-3">Открыть хосты</LinkButton></div>
        </div>
      ) : null}
      {preparation?.astraOval && preparation.openScap ? (
        <>
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            <SourceCard title="Astra Linux: CVE по OVAL" source={preparation.astraOval}
              href="/data-sources#astra-oval-title" linkText="Настроить OVAL"
              description="Только для Astra соответствующего выпуска и архитектуры; наличие XML и SHA не означает подтверждённую подлинность производителя." />
            <SourceCard title="Конфигурация: профиль OpenSCAP" source={preparation.openScap}
              href="/policies" linkText="Настроить профиль"
              description="Проверяет настройки в области выбранного XCCDF/SCE-профиля. Авторский профиль Astra не является официальным стандартом соответствия." />
          </div>
          <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-amber-100">
            <FileCheck2 size={16} className="mt-0.5 shrink-0" aria-hidden="true"/>
            {preparation.warning}
          </p>
          <LinkButton href={`/hosts?host=${encodeURIComponent(alias)}#ansible-actions`} variant="secondary" className="mt-3">
            Перейти к проверкам хоста
          </LinkButton>
        </>
      ) : null}
    </section>
  );
}
