"use client";

import { ChevronDown, Copy, KeyRound, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

type Props = {
  access: { ok?: boolean; publicKey?: string; fingerprint?: string | null; message?: string } | null;
  loading: string;
  message: string;
  address: string;
  command: string;
  copied: string;
  fingerprints?: Array<{ fingerprint: string; algorithm: string }>;
  trustedFingerprint: string;
  onFingerprint: (value: string) => void;
  onRefresh: () => void;
  onCopy: (value: string, label: string) => void;
  onScan: () => void;
  onTrust: () => void;
};

export function SshConnectionHelp(props: Props) {
  const { access, loading, address } = props;
  return <section className="mt-5 overflow-hidden rounded-xl border border-slate-700/70 bg-slate-900/40" aria-labelledby="connection-wizard-title">
    <div className="flex flex-col gap-4 p-4 sm:flex-row sm:items-start sm:justify-between sm:p-5">
      <div className="flex min-w-0 gap-3">
        <KeyRound size={22} className="mt-0.5 shrink-0 text-sky-300" aria-hidden="true" />
        <div>
          <h3 id="connection-wizard-title" className="font-semibold text-white">Доступ по SSH</h3>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">Если доступ платформе уже выдан, нажмите «Проверить подключение». Для первого подключения используйте единый порядок: ключ платформы, режим sudo, подтверждение ключа сервера, проверка и сохранение.</p>
        </div>
      </div>
      <Button variant="secondary" onClick={props.onRefresh} disabled={Boolean(loading)} className="w-full sm:w-auto" title="Повторно прочитать текущий ключ платформы">
        <RefreshCw size={16} className={loading === "key" ? "animate-spin" : ""} aria-hidden="true" />
        {loading === "key" ? "Читаем ключ…" : "Обновить сведения"}
      </Button>
    </div>
    <details className="group/key border-t border-slate-800">
      <summary className="flex cursor-pointer items-center justify-between gap-3 px-5 py-4 text-sm font-medium text-slate-200">
        <span>Ключ платформы <span className="ml-2 text-xs font-normal text-slate-400">Для входа на хост</span></span>
        <ChevronDown size={18} className="shrink-0 transition group-open/key:rotate-180" aria-hidden="true" />
      </summary>
      <div className="space-y-4 px-5 pb-5">
        <p className="text-sm leading-6 text-slate-400">Это публичная часть ключа, которым платформа подключается к хостам. «Обновить сведения» перечитывает его; замена ключа этой кнопкой не выполняется.</p>
        {access?.ok && access.publicKey ? <>
          <label className="block text-sm text-slate-300">Публичный SSH-ключ
            <textarea readOnly value={access.publicKey} rows={3} spellCheck={false} onFocus={(event) => event.target.select()}
              className="mt-2 block w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-6 text-sky-100" />
          </label>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <Button variant="secondary" onClick={() => props.onCopy(access.publicKey ?? "", "public-key")}>
              <Copy size={16} aria-hidden="true" />{props.copied === "public-key" ? "Скопировано" : "Скопировать ключ"}
            </Button>
            <p className="min-w-0 break-all font-mono text-xs leading-5 text-slate-400">Отпечаток: {access.fingerprint ?? "не определён"}</p>
          </div>
          <details className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
            <summary className="cursor-pointer text-sm text-sky-200">Если доступ этому ключу ещё не выдан</summary>
            <p className="mt-3 text-sm leading-6 text-slate-400">Текущая версия использует ключ платформы и не принимает пароль SSH или личный ключ через сайт. Администратор хоста должен разрешить доступ этому ключу. Если он уже разрешён, повторная настройка не нужна.</p>
            <p className="mt-2 text-sm leading-6 text-slate-400">Команда для администратора: выполнить на целевом хосте от имени указанного пользователя SSH.</p>
            <textarea aria-label="Команда добавления публичного ключа" readOnly value={props.command} rows={4} spellCheck={false} onFocus={(event) => event.target.select()}
              className="mt-3 block w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-6 text-slate-300" />
            <Button variant="secondary" className="mt-3" onClick={() => props.onCopy(props.command, "install-command")}><Copy size={16} aria-hidden="true" />{props.copied === "install-command" ? "Скопировано" : "Скопировать команду"}</Button>
          </details>
        </> : <p className="rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-sm leading-6 text-amber-100">{loading === "key" ? "Читаем ключ платформы…" : access?.message ?? "Ключ пока недоступен. Обновите сведения."}</p>}
      </div>
    </details>
    <details className="group/server border-t border-slate-800">
      <summary className="flex cursor-pointer items-center justify-between gap-3 px-5 py-4 text-sm font-medium text-slate-200">
        <span>Ключ сервера <span className="ml-2 text-xs font-normal text-slate-400">Проверка подлинности хоста</span></span>
        <ChevronDown size={18} className="shrink-0 transition group-open/server:rotate-180" aria-hidden="true" />
      </summary>
      <div className="space-y-4 px-5 pb-5">
        <p className="max-w-3xl text-sm leading-6 text-slate-400">При первом подключении сверьте SHA256-отпечаток сервера с доверенным реестром или консолью гипервизора. Получение ключа по сети само по себе не подтверждает его подлинность.</p>
        <Button variant="secondary" onClick={props.onScan} disabled={Boolean(loading) || !address}>
          <Search size={16} className={loading === "scan" ? "animate-pulse" : ""} aria-hidden="true" />{loading === "scan" ? "Получаем отпечатки…" : "Получить отпечатки по сети"}
        </Button>
        {!address ? <p className="text-xs text-slate-400">Сначала укажите адрес хоста в форме выше.</p> : null}
        {props.fingerprints?.length ? <div className="space-y-2 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3" aria-label="Неподтверждённые отпечатки">
          {props.fingerprints.map((item) => <p key={`${item.algorithm}-${item.fingerprint}`} className="break-all font-mono text-xs leading-6 text-amber-100">{item.algorithm}: {item.fingerprint}</p>)}
        </div> : null}
        <label className="block max-w-2xl text-sm text-slate-300">Подтверждённый SHA256-отпечаток
          <input value={props.trustedFingerprint} onChange={(event) => props.onFingerprint(event.target.value)} placeholder="SHA256:…" spellCheck={false}
            className="mt-2 h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 font-mono text-sm text-slate-100 focus:border-sky-300 focus:outline-none" />
        </label>
        <Button onClick={props.onTrust} disabled={Boolean(loading) || !address || !props.trustedFingerprint}>
          <ShieldCheck size={16} className={loading === "trust" ? "animate-pulse" : ""} aria-hidden="true" />{loading === "trust" ? "Сохраняем…" : "Сохранить проверенный ключ"}
        </Button>
      </div>
    </details>
    {props.message ? <p className="border-t border-slate-800 px-5 py-3 text-sm leading-6 text-slate-300">{props.message}</p> : null}
  </section>;
}
