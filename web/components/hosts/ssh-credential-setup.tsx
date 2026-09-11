"use client";

import { useEffect, useState } from "react";
import { KeyRound, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

export type CredentialSetupResult = {
  ok: boolean; credentialId?: string; publicKey?: string | null; fingerprint?: string | null; message?: string;
  sudo?: { requested: boolean; ready: boolean; configured: boolean };
};
export type SetupSecrets = { password: string; sudoPassword: string; configureSudo: boolean };

export function SshCredentialSetup({ loading, canConnect, result, legacy, onSetup }: {
  loading: boolean; canConnect: boolean; result: CredentialSetupResult | null; legacy: boolean;
  onSetup: (secrets: SetupSecrets) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [sudoPassword, setSudoPassword] = useState("");
  const [configureSudo, setConfigureSudo] = useState(false);
  const [secure, setSecure] = useState(false);
  useEffect(() => {
    setSecure(window.location.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]", "::1"].includes(window.location.hostname));
  }, []);
  async function setup() {
    const secrets = { password, sudoPassword, configureSudo };
    setPassword(""); setSudoPassword("");
    try { await onSetup(secrets); }
    finally { secrets.password = ""; secrets.sudoPassword = ""; }
  }
  return <div id="ssh-setup" className="mt-4 scroll-mt-6 rounded-xl border border-sky-400/20 bg-sky-400/5 p-4">
    <h3 className="flex items-center gap-2 font-semibold text-white"><KeyRound size={20} aria-hidden="true" />Вход по паролю и отдельный SSH-ключ</h3>
    <p className="mt-2 text-sm leading-6 text-slate-300">Введите пароль пользователя SSH. HCP войдёт на выбранную машину, создаст для неё отдельную пару на Ubuntu, установит публичный ключ и проверит новый вход без пароля.</p>
    <p className="mt-2 text-xs leading-5 text-slate-400">Приватный ключ остаётся в HCP. Пароль используется только для этой операции и не записывается в базу или журнал. Повторная попытка использует уже созданную для этого подключения пару.</p>
    {legacy ? <p className="mt-3 text-sm text-amber-100">Этот хост пока использует прежний общий ключ. Здесь можно перевести его на отдельный ключ, затем сохранить изменения.</p> : null}
    {!secure ? <p className="mt-3 rounded-lg border border-amber-400/30 p-3 text-sm leading-6 text-amber-100">Для ввода пароля откройте панель через HTTPS или на самой Ubuntu по адресу http://127.0.0.1 с вашим портом HCP. Обычный HTTP по локальной сети не шифрует пароль.</p> : null}
    <fieldset disabled={loading || !secure} className="mt-4 space-y-3">
      <label className="block max-w-xl text-sm text-slate-300">Пароль пользователя SSH
        <input type="password" autoComplete="off" value={password} onChange={(event) => setPassword(event.target.value)} maxLength={1024}
          placeholder={result?.credentialId ? "Для повторной настройки при необходимости" : "Пароль учётной записи на Astra"}
          className="mt-2 block h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-100 focus:border-sky-300 focus:outline-none" />
      </label>
      <label className="flex items-start gap-3 rounded-lg border border-slate-700 p-3 text-sm leading-6 text-slate-300">
        <input type="checkbox" checked={configureSudo} onChange={(event) => setConfigureSudo(event.target.checked)} className="mt-1 h-4 w-4 shrink-0" />
        <span>Настроить беспарольное sudo для этой учётной записи — <strong className="text-white">полные права root</strong> для последующих аудитов и изменений.
          <span className="mt-1 block text-xs leading-5 text-slate-400">Нужны уже имеющиеся административные права. HCP проверит правило через visudo. Если sudo уже настроено, оставьте опцию выключенной.</span>
        </span>
      </label>
      {configureSudo ? <label className="block max-w-xl text-sm text-slate-300">Пароль sudo, если отличается от пароля SSH
        <input type="password" autoComplete="off" value={sudoPassword} onChange={(event) => setSudoPassword(event.target.value)} maxLength={1024} placeholder="Пустое поле — использовать пароль SSH"
          className="mt-2 block h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-slate-100 focus:border-sky-300 focus:outline-none" />
      </label> : null}
      <Button onClick={() => void setup()} disabled={!canConnect || (!password && !result?.credentialId)}>
        {loading ? <LoaderCircle size={18} className="animate-spin" aria-hidden="true" /> : <KeyRound size={18} aria-hidden="true" />}
        {loading ? "Настраиваем подключение…" : result?.credentialId ? "Проверить ключ и настройки sudo" : "Создать ключ и настроить доступ"}
      </Button>
    </fieldset>
    {!canConnect ? <p className="mt-2 text-xs text-slate-400">Сначала заполните имя хоста, адрес, порт и пользователя в форме выше.</p> : null}
    {result?.credentialId ? <div className="mt-4 rounded-lg border border-emerald-400/25 bg-emerald-400/5 p-3">
      <p className="text-sm font-medium text-emerald-100">{result.ok ? "Отдельный ключ этого хоста готов" : "Требуется проверка SSH-ключа"}</p>
      <p className="mt-2 break-all font-mono text-xs text-slate-300">{result.fingerprint}</p>
      <details className="mt-2"><summary className="cursor-pointer text-sm text-sky-200">Показать публичный ключ</summary>
        <textarea readOnly aria-label="Публичный ключ этого хоста" value={result.publicKey ?? ""} rows={3} spellCheck={false} onFocus={(event) => event.target.select()}
          className="mt-2 block w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-6 text-slate-300" />
      </details>
    </div> : null}
    {result?.message ? <p className={`mt-3 text-sm leading-6 ${result.ok ? "text-slate-300" : "text-red-200"}`} role="status">{result.message}</p> : null}
  </div>;
}
