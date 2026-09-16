"use client";

import { Copy, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

const fingerprintCommand = `for key in /etc/ssh/ssh_host_*_key.pub; do
  [ -f "$key" ] && ssh-keygen -lf "$key" -E sha256
done`;

type TrustProps = {
  expanded: boolean; onExpanded: (value: boolean) => void;
  loading: string; address: string; port: string; message: string; trusted: boolean;
  fingerprints?: Array<{ fingerprint: string; algorithm: string }>;
  trustedFingerprint: string;
  onFingerprint: (value: string) => void;
  onScan: () => void;
  onTrust: () => void;
  onCopy: (value: string, label: string) => void;
};

export function HostServerTrust(props: TrustProps) {
  return <details open={props.expanded} onToggle={(event) => props.onExpanded(event.currentTarget.open)} className="rounded-lg border border-slate-800 p-3 sm:p-4">
    <summary className="cursor-pointer text-sm text-slate-300">{props.trusted ? "Ключ сервера сохранён" : "Проверка Astra перед первым входом"}</summary>
    <h3 className="mt-3 font-semibold text-white">Целевая Astra {props.address ? <span className="break-all text-sky-200">{props.address}:{props.port}</span> : null}</h3>
    {props.trusted ? <p className="mt-3 text-sm leading-6 text-emerald-200" role="status">Ключ сервера сохранён. Продолжите кнопкой «Подключить хост» или «Сохранить подключение». При входе HCP автоматически проверит, что ключ не изменился.</p> : <>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">Сначала подтверждаем сервер, затем передаём пароль. HCP может получить публичный ключ Astra без входа в её учётную запись.</p>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Сравниваем отпечаток одной и той же Astra из двух источников: её доверенной консоли и сети. Ключ управляющей Ubuntu в этой проверке не участвует.</p>
      <fieldset disabled={Boolean(props.loading)} className="mt-4 grid min-w-0 gap-3 lg:grid-cols-2">
        <section className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
          <h4 className="text-sm font-semibold text-white">1. Получите отпечаток на целевой Astra</h4>
          <p className="mt-2 text-sm leading-6 text-slate-400">Возьмите его из доверенного реестра администратора либо откройте консоль этой ВМ в гипервизоре и выполните команду:</p>
          <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-slate-950 p-3 text-xs leading-6 text-sky-100">{fingerprintCommand}</pre>
          <Button type="button" variant="secondary" className="mt-2" onClick={() => props.onCopy(fingerprintCommand, "server-fingerprint")}><Copy size={16} aria-hidden="true" />Скопировать команду</Button>
          <p className="mt-3 text-xs leading-5 text-slate-400">Команда показывает существующие ключи и ничего не создаёт. Скопируйте одно значение SHA256:… без пробелов. Если строк несколько, достаточно одного ключа, который использует SSH-сервер.</p>
          <details className="mt-3 text-xs leading-5 text-slate-400">
            <summary className="cursor-pointer text-sky-200">Команда ничего не вывела?</summary>
            <p className="mt-2">Публичные файлы могут находиться в другом каталоге. Администратор может посмотреть пути HostKey командой <code className="break-all text-slate-200">sudo /usr/sbin/sshd -T</code> с используемым файлом конфигурации. Отсутствие файла ED25519 не означает, что SSH не работает.</p>
          </details>
        </section>
        <section className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
          <h4 className="text-sm font-semibold text-white">2. Вставьте отпечаток — HCP сверит его по сети</h4>
          <label className="mt-3 block text-sm text-slate-300">Отпечаток из консоли Astra или реестра
            <input value={props.trustedFingerprint} onChange={(event) => props.onFingerprint(event.target.value)} placeholder="SHA256:…" spellCheck={false}
              className="mt-2 h-11 w-full min-w-0 rounded-lg border border-slate-700 bg-slate-950 px-3 font-mono text-sm text-slate-100 focus:border-sky-300 focus:outline-none" />
          </label>
          <Button type="button" className="mt-3" onClick={props.onTrust} disabled={!props.address || !props.trustedFingerprint.trim()}><ShieldCheck size={16} aria-hidden="true" />{props.loading === "trust" ? "Сверяем…" : "Сверить и сохранить"}</Button>
          <p className="mt-3 text-sm leading-6 text-slate-400">HCP сам получит ключ с указанного адреса и сохранит его только при совпадении. Отдельно нажимать «Получить отпечатки по сети» не требуется.</p>
          <p className="mt-2 text-sm leading-6 text-slate-400">Затем нажмите «Подключить хост». Пароль будет отправлен после проверки сохранённого ключа.</p>
        </section>
      </fieldset>
      <details className="mt-3 text-sm">
        <summary className="cursor-pointer text-sky-200">Посмотреть отпечатки, полученные по сети</summary>
        <p className="mt-2 text-xs leading-5 text-slate-400">Это ключи целевой Astra, увиденные с Ubuntu. Сверяйте одинаковый тип ключа: ED25519 с ED25519, RSA с RSA. Отпечатки разных типов отличаются. Для подтверждения нужен второй источник — консоль Astra или доверенный реестр.</p>
        <Button type="button" variant="secondary" className="mt-2" onClick={props.onScan} disabled={Boolean(props.loading) || !props.address}><Search size={16} aria-hidden="true" />Получить отпечатки по сети</Button>
        {props.fingerprints?.map((item) => <p key={`${item.algorithm}-${item.fingerprint}`} className="mt-2 break-all font-mono text-xs leading-6 text-slate-300">{item.algorithm}: {item.fingerprint}</p>)}
      </details>
      {props.message ? <p className="mt-3 text-sm leading-6 text-slate-300" role="status">{props.message}</p> : null}
    </>}
    <details className="mt-3 text-sm">
      <summary className="cursor-pointer text-sky-200">Если хостов много</summary>
      <p className="mt-2 text-xs leading-5 text-slate-400">Администратор может собрать ключи при развёртывании машин или через уже доверенную систему управления и вести реестр: адрес, порт, тип ключа и отпечаток. Для каждого нового хоста берите значение из этого реестра. Сохранённые ключи HCP проверяет автоматически при следующих подключениях.</p>
      <a href="https://github.com/Danil-super/hardening-control-platform/blob/main/docs/ubuntu-astra-setup.md#host-trust-fleet" target="_blank" rel="noreferrer" className="mt-2 inline-block text-xs text-sky-200 underline underline-offset-4">Реестр и подготовка known_hosts для первого запуска</a>
    </details>
  </details>;
}
