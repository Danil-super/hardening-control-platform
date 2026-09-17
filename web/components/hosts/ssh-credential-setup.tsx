"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowRight, CheckCircle2, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { onboardingSecretsForUser, type OnboardingSecrets } from "@/lib/host-onboarding";

export type CredentialSetupResult = {
  ok: boolean; credentialId?: string; publicKey?: string | null; fingerprint?: string | null; message?: string;
  sudo?: { requested: boolean; ready: boolean; configured: boolean };
};
export type SetupSecrets = OnboardingSecrets;

export function SshCredentialSetup({ loading, canConnect, result, legacy, editing, user, children, onSetup }: {
  loading: string; canConnect: boolean; result: CredentialSetupResult | null; legacy: boolean; editing: boolean; user: string; children?: ReactNode;
  onSetup: (secrets: SetupSecrets, clearPasswords: () => void) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [sudoPassword, setSudoPassword] = useState("");
  const [secure, setSecure] = useState(false);
  const submitting = useRef(false);
  const existingAccess = Boolean(result?.credentialId || legacy);
  const isRoot = user.trim() === "root";
  // A key retained after a failed first attempt proves SSH only.  Until the
  // host is saved, a non-root account must submit its password so HCP can
  // finish the one-time non-interactive sudo setup.  Existing saved hosts may
  // still be checked without a password.
  const needsInitialPrivilegeSetup = !editing && !isRoot && result?.sudo?.ready !== true;
  const passwordRequired = !existingAccess || needsInitialPrivilegeSetup;
  useEffect(() => {
    setSecure(window.location.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]", "::1"].includes(window.location.hostname));
  }, []);
  async function setup() {
    if (submitting.current || loading || !canConnect || (passwordRequired && !password) || (!secure && Boolean(password))) return;
    submitting.current = true;
    // A non-root account needs a non-interactive privilege path after the
    // one-time password disappears.  The password is used only in this
    // request to install the HCP-managed sudoers entry and is never stored.
    const secrets = onboardingSecretsForUser(user, password, sudoPassword);
    try { await onSetup(secrets, () => { setPassword(""); setSudoPassword(""); }); }
    finally { secrets.password = ""; secrets.sudoPassword = ""; submitting.current = false; }
  }
  const progress: Record<string, string> = {
    "connect-trust": "Проверяем сервер…",
    "connect-bootstrap": "Входим и настраиваем ключ…",
    "connect-preflight": "Проверяем доступ администратора…",
    "connect-save": "Сохраняем хост…",
  };
  return <form id="ssh-setup" onSubmit={(event) => { event.preventDefault(); void setup(); }} className="mt-4 scroll-mt-6">
    <fieldset disabled={Boolean(loading)} className="space-y-4">
      <label className="block max-w-xl text-sm font-medium text-slate-200">Пароль администратора Astra
        <input type="password" autoComplete="off" value={password} disabled={!secure} onChange={(event) => setPassword(event.target.value)} maxLength={1024}
          placeholder={needsInitialPrivilegeSetup && existingAccess ? "Введите пароль для завершения настройки прав" : existingAccess ? "Можно оставить пустым — ключ уже настроен" : "Пароль для входа на выбранный хост"}
          className="mt-2 block h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-100 focus:border-sky-300 focus:outline-none disabled:opacity-50" />
      </label>
      {!isRoot ? <details className="max-w-xl rounded-lg border border-slate-800 px-3 py-2">
        <summary className="cursor-pointer text-sm text-slate-300">Пароль для повышения прав отличается от пароля SSH</summary>
        <label className="mt-3 block text-sm font-medium text-slate-200">Пароль для повышения прав
          <input type="password" autoComplete="off" value={sudoPassword} disabled={!secure} onChange={(event) => setSudoPassword(event.target.value)} maxLength={1024}
            placeholder="Оставьте пустым, если пароль тот же"
            className="mt-2 block h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-100 focus:border-sky-300 focus:outline-none disabled:opacity-50" />
        </label>
      </details> : null}
      <p className="max-w-2xl text-sm leading-6 text-slate-400">Входить через терминал и создавать ключи вручную не нужно. Для пользователя не root HCP использует введённый пароль один раз, включает постоянное повышение прав для этой учётной записи и затем работает только по отдельному ключу. Пароль не сохраняется.</p>
      {!secure ? <p className="rounded-lg border border-amber-400/30 p-3 text-sm leading-6 text-amber-100">Для ввода пароля откройте HCP через HTTPS или http://127.0.0.1 с вашим портом на Ubuntu. С другого компьютера можно использовать SSH-туннель — порядок есть в инструкции.</p> : null}
      {children}
      <div className="rounded-lg bg-sky-400/5 p-4">
        <p className="text-sm font-medium text-slate-200">После нажатия HCP всё выполнит по порядку:</p>
        <ol className="mt-2 grid gap-2 text-sm leading-6 text-slate-400 sm:grid-cols-3">
          <li><span className="text-sky-200">1.</span> Войдёт на Astra по паролю.</li>
          <li><span className="text-sky-200">2.</span> Создаст отдельную пару на Ubuntu и установит публичный ключ на Astra.</li>
          <li><span className="text-sky-200">3.</span> Проверит вход по ключу, права администратора и сохранит хост.</li>
        </ol>
        {existingAccess ? <p className="mt-2 text-xs leading-5 text-slate-400">{needsInitialPrivilegeSetup
          ? "Ключ SSH уже создан, но хост ещё не добавлен: введите пароль ещё раз, чтобы HCP завершил автоматическую настройку sudo. Эта попытка использует ту же ключевую пару."
          : "Для уже настроенного подключения HCP использует сохранённый ключ. Новый пароль нужен только при настройке другого доступа."}</p> : null}
        <p className="mt-2 text-xs leading-5 text-slate-400">У каждого хоста своя пара. Приватный ключ остаётся на Ubuntu. Пароль не сохраняется.</p>
      </div>
      {legacy ? <p className="text-sm leading-6 text-amber-100">Этот хост использует прежний общий ключ. Чтобы перейти на отдельную пару, введите пароль выше и сохраните подключение.</p> : null}
      <Button type="submit" disabled={Boolean(loading) || !canConnect || (passwordRequired && !password) || (!secure && Boolean(password))} className="w-full sm:w-auto">
        {loading ? <LoaderCircle size={18} className="animate-spin" aria-hidden="true" /> : <ArrowRight size={18} aria-hidden="true" />}
        {progress[loading] ?? (loading ? "Подождите…" : editing ? "Сохранить подключение" : "Подключить хост")}
      </Button>
    </fieldset>
    {!canConnect ? <p className="mt-2 text-xs text-slate-400">Укажите адрес и пользователя Astra в форме выше.</p> : null}
    {needsInitialPrivilegeSetup && existingAccess ? <p className="mt-2 text-xs leading-5 text-amber-100">Проверка Ansible пока не запускается: без этого одноразового пароля HCP не может сделать дальнейшие аудиты и харденинг беспарольными.</p> : null}
    {result?.credentialId ? <details className="mt-4 rounded-lg border border-slate-800 p-3">
      <summary className="cursor-pointer text-sm text-slate-300"><CheckCircle2 size={16} className="mr-2 inline text-emerald-300" aria-hidden="true" />Ключ этого хоста сохранён — сведения</summary>
      <p className="mt-2 break-all font-mono text-xs text-slate-300">{result.fingerprint}</p>
      <textarea readOnly aria-label="Публичный ключ этого хоста" value={result.publicKey ?? ""} rows={3} spellCheck={false} onFocus={(event) => event.target.select()}
        className="mt-2 block w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-6 text-slate-300" />
    </details> : null}
    {result?.message ? <p className={`mt-3 text-sm leading-6 ${result.ok ? "text-slate-300" : "text-red-200"}`} role="status">{result.message}</p> : null}
  </form>;
}
