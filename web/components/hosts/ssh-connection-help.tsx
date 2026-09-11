"use client";

import { Copy, KeyRound, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

type KeyProps = {
  access: { ok?: boolean; publicKey?: string; fingerprint?: string | null; message?: string } | null;
  loading: string;
  command: string;
  user: string;
  copied: string;
  onRefresh: () => void;
  onCopy: (value: string, label: string) => void;
};

export function SshConnectionHelp({ access, loading, command, user, copied, onRefresh, onCopy }: KeyProps) {
  const account = /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(user) ? user : "ИМЯ_ПОЛЬЗОВАТЕЛЯ_SSH";
  return <section id="ssh-setup" className="scroll-mt-6 rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5" aria-labelledby="ssh-setup-title">
    <div className="flex items-start gap-3">
      <KeyRound size={22} className="mt-1 shrink-0 text-sky-300" aria-hidden="true" />
      <div>
        <h2 id="ssh-setup-title" className="text-lg font-semibold text-white">2. Первое подключение по SSH</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">Если подключаете хост впервые, подготовьте доступ на самой Astra. Если ключ и sudo уже настроены, переходите к форме ниже.</p>
      </div>
    </div>
    <div className="mt-5 grid gap-4 xl:grid-cols-2">
      <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <h3 className="font-semibold text-white">Разрешите вход по ключу</h3>
        <p className="mt-2 text-sm leading-6 text-slate-300">На целевой Astra войдите под пользователем, которого будете указывать в поле «Пользователь SSH», и выполните эту команду:</p>
        {access?.ok && access.publicKey ? <>
          <textarea aria-label="Команда добавления публичного ключа" readOnly value={command} rows={5} spellCheck={false} onFocus={(event) => event.target.select()}
            className="mt-3 block w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-6 text-sky-100" />
          <Button variant="secondary" className="mt-3" onClick={() => onCopy(command, "install-command")}>
            <Copy size={16} aria-hidden="true" />{copied === "install-command" ? "Скопировано" : "Скопировать команду"}
          </Button>
        </> : <div className="mt-3 space-y-3 text-sm text-amber-100">
          <p>{loading === "key" ? "Загружаем ключ платформы…" : access?.message ?? "Ключ платформы пока недоступен."}</p>
          <Button variant="secondary" onClick={onRefresh} disabled={Boolean(loading)}>Повторить загрузку ключа</Button>
        </div>}
        <p className="mt-3 text-xs leading-5 text-slate-400">Имя текущего пользователя покажет <code className="text-sky-200">id -un</code>. Укажите это же имя в форме. На каждой новой машине команда выполняется один раз; повторный запуск не дублирует ключ.</p>
      </div>
      <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/40 p-4">
        <h3 className="font-semibold text-white">Подготовьте sudo для аудита и изменений</h3>
        <p className="mt-2 text-sm leading-6 text-slate-300">Администратор в root-сеансе на Astra открывает правило:</p>
        <code className="mt-2 block break-all rounded-lg bg-slate-950 p-3 text-xs leading-6 text-sky-100">visudo -f /etc/sudoers.d/90-hcp-audit</code>
        <p className="mt-3 text-sm leading-6 text-slate-300">И добавляет строку для того же пользователя SSH:</p>
        <code className="mt-2 block break-all rounded-lg bg-slate-950 p-3 text-xs leading-6 text-sky-100">{account} ALL=(root) NOPASSWD: ALL</code>
        <p className="mt-2 text-xs leading-5 text-slate-400">{account === "ИМЯ_ПОЛЬЗОВАТЕЛЯ_SSH" ? "Замените ИМЯ_ПОЛЬЗОВАТЕЛЯ_SSH на результат id -un из шага слева." : `Правило показано для пользователя ${account} из формы ниже.`} Это полные права root без пароля. Пример предназначен для выделенной учётной записи вашего стенда.</p>
        <p className="mt-3 text-sm leading-6 text-slate-300">Администратор проверяет файл командой <code className="text-sky-200">visudo -c</code>. Затем пользователь SSH выполняет <code className="text-sky-200">sudo -k -n id -u</code> — ожидается <strong>0</strong> без запроса пароля.</p>
        <a href="/guide#sudo-access" className="mt-3 inline-block text-sm text-sky-300 underline underline-offset-4">Полная инструкция sudo и разбор ошибок</a>
      </div>
    </div>
    <p className="mt-4 text-sm leading-6 text-slate-300"><strong className="text-white">Публичный ключ общий для всех хостов этой установки HCP.</strong> Он остаётся тем же после перезапуска. На каждый целевой хост передаётся только публичная часть.</p>
    <a href="#host-form" className="mt-3 inline-block text-sm font-medium text-sky-300 underline underline-offset-4">Доступ подготовлен — перейти к форме добавления</a>
    <details className="mt-3 rounded-lg border border-slate-800 p-3">
      <summary className="cursor-pointer text-sm text-sky-200">Показать публичный ключ и порядок его замены</summary>
      <p className="mt-3 text-sm leading-6 text-slate-400">Замена ключа затрагивает все подключённые хосты: новый публичный ключ сначала нужно разрешить на каждом из них. <a href="https://github.com/Danil-super/hardening-control-platform/blob/main/docs/ubuntu-astra-setup.md#key-rotation" className="text-sky-300 underline underline-offset-4">Порядок замены ключа</a>.</p>
      {access?.publicKey ? <>
        <textarea aria-label="Публичный SSH-ключ" readOnly value={access.publicKey} rows={3} spellCheck={false} onFocus={(event) => event.target.select()}
          className="mt-3 block w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-6 text-sky-100" />
        <p className="mt-2 break-all font-mono text-xs text-slate-400">Отпечаток: {access.fingerprint ?? "не определён"}</p>
      </> : null}
      <div className="mt-3 flex flex-wrap gap-3">
        <Button variant="secondary" onClick={() => onCopy(access?.publicKey ?? "", "public-key")} disabled={!access?.publicKey}><Copy size={16} aria-hidden="true" />Скопировать ключ</Button>
        <Button variant="secondary" onClick={onRefresh} disabled={Boolean(loading)}><RefreshCw size={16} className={loading === "key" ? "animate-spin" : ""} aria-hidden="true" />Перечитать ключ</Button>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-400">«Перечитать ключ» загружает текущий ключ из HCP. Новый ключ эта кнопка не создаёт.</p>
    </details>
  </section>;
}

type TrustProps = {
  loading: string; address: string; port: string; message: string; trusted: boolean;
  fingerprints?: Array<{ fingerprint: string; algorithm: string }>;
  trustedFingerprint: string;
  onFingerprint: (value: string) => void;
  onScan: () => void;
  onTrust: () => void;
  onCopy: (value: string, label: string) => void;
};

export function HostServerTrust(props: TrustProps) {
  return <div className="mt-4 rounded-lg border border-slate-700 bg-slate-900/40 p-4">
    <h3 className="font-semibold text-white">Подтверждение сервера {props.address ? <span className="break-all text-sky-200">{props.address}:{props.port}</span> : null}</h3>
    <p className="mt-2 text-sm leading-6 text-slate-400">При первом подключении подтвердите, что это нужная машина. В доверенной консоли Astra выполните команду и скопируйте значение SHA256:…:</p>
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <code className="min-w-0 break-all rounded-lg bg-slate-950 p-3 text-xs leading-6 text-sky-100">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256</code>
      <Button variant="secondary" onClick={() => props.onCopy("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256", "server-fingerprint")}><Copy size={16} aria-hidden="true" />Скопировать команду</Button>
    </div>
    <p className="mt-2 text-xs leading-5 text-slate-400">Если ED25519-ключа нет, используйте существующий публичный RSA/ECDSA-ключ сервера. Для ранее подтверждённого сервера этот шаг можно пропустить.</p>
    <div className="mt-3 flex flex-wrap items-end gap-3">
      <label className="block min-w-0 flex-1 text-sm text-slate-300">Отпечаток из консоли Astra
        <input value={props.trustedFingerprint} onChange={(event) => props.onFingerprint(event.target.value)} placeholder="SHA256:…" spellCheck={false}
          className="mt-2 h-11 w-full min-w-56 rounded-lg border border-slate-700 bg-slate-950 px-3 font-mono text-sm text-slate-100 focus:border-sky-300 focus:outline-none" />
      </label>
      <Button onClick={props.onTrust} disabled={Boolean(props.loading) || !props.address || !props.trustedFingerprint}><ShieldCheck size={16} aria-hidden="true" />{props.loading === "trust" ? "Подтверждаем…" : "Подтвердить сервер"}</Button>
    </div>
    {props.trusted ? <p className="mt-3 text-sm text-emerald-200" role="status">Сервер подтверждён. Теперь проверьте подключение кнопкой ниже.</p> : null}
    <details className="mt-3 text-sm">
      <summary className="cursor-pointer text-sky-200">Сравнить с отпечатками, полученными по сети</summary>
      <p className="mt-2 text-xs leading-5 text-slate-400">Сетевые отпечатки нужно сверить с консолью или доверенным реестром.</p>
      <Button variant="secondary" className="mt-2" onClick={props.onScan} disabled={Boolean(props.loading) || !props.address}><Search size={16} aria-hidden="true" />Получить отпечатки по сети</Button>
      {!props.address ? <p className="mt-2 text-xs text-slate-400">Сначала укажите адрес в форме выше.</p> : null}
      {props.fingerprints?.map((item) => <p key={`${item.algorithm}-${item.fingerprint}`} className="mt-2 break-all font-mono text-xs leading-6 text-slate-300">{item.algorithm}: {item.fingerprint}</p>)}
    </details>
    {props.message && !props.trusted ? <p className="mt-3 text-sm leading-6 text-slate-300">{props.message}</p> : null}
  </div>;
}
