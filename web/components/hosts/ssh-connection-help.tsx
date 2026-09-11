"use client";

import { Copy, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

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
  return <details open={props.expanded} onToggle={(event) => props.onExpanded(event.currentTarget.open)} className="rounded-lg border border-slate-800 p-3">
    <summary className="cursor-pointer text-sm text-slate-300">{props.trusted ? "Сервер подтверждён" : "Проверка сервера — только при первом подключении"}</summary>
    <h3 className="mt-3 font-semibold text-white">Подтверждение сервера {props.address ? <span className="break-all text-sky-200">{props.address}:{props.port}</span> : null}</h3>
    <p className="mt-2 text-sm leading-6 text-slate-400">Перед первым входом убедитесь, что это нужная Astra. Вставьте отпечаток её SSH-сервера из доверенного реестра или получите его у администратора. HCP проверяет его до передачи пароля.</p>
    <details className="mt-3 text-sm">
      <summary className="cursor-pointer text-sky-200">Где взять отпечаток, если реестра нет?</summary>
      <p className="mt-2 text-xs leading-5 text-slate-400">В консоли этой Astra выполните команду ниже. Она только читает отпечаток уже существующего ключа сервера. Пару для доступа HCP платформа создаст сама после входа по паролю.</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <code className="min-w-0 break-all rounded-lg bg-slate-950 p-3 text-xs leading-6 text-sky-100">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256</code>
        <Button type="button" variant="secondary" onClick={() => props.onCopy("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256", "server-fingerprint")}><Copy size={16} aria-hidden="true" />Скопировать команду</Button>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-400">При отсутствии ED25519 используйте существующий публичный RSA/ECDSA-ключ сервера.</p>
    </details>
    <div className="mt-3 flex flex-wrap items-end gap-3">
      <label className="block min-w-0 flex-1 text-sm text-slate-300">Отпечаток сервера из доверенного источника
        <input value={props.trustedFingerprint} onChange={(event) => props.onFingerprint(event.target.value)} placeholder="SHA256:…" spellCheck={false}
          className="mt-2 h-11 w-full min-w-56 rounded-lg border border-slate-700 bg-slate-950 px-3 font-mono text-sm text-slate-100 focus:border-sky-300 focus:outline-none" />
      </label>
      <Button type="button" onClick={props.onTrust} disabled={Boolean(props.loading) || !props.address || !props.trustedFingerprint}><ShieldCheck size={16} aria-hidden="true" />{props.loading === "trust" ? "Подтверждаем…" : "Подтвердить сервер"}</Button>
    </div>
    {props.trusted ? <p className="mt-3 text-sm text-emerald-200" role="status">Сервер подтверждён. Нажмите «Подключить хост» или «Сохранить подключение».</p> : null}
    <details className="mt-3 text-sm">
      <summary className="cursor-pointer text-sky-200">Сравнить с отпечатками, полученными по сети</summary>
      <p className="mt-2 text-xs leading-5 text-slate-400">Сетевые отпечатки нужно сверить с консолью или доверенным реестром.</p>
      <Button type="button" variant="secondary" className="mt-2" onClick={props.onScan} disabled={Boolean(props.loading) || !props.address}><Search size={16} aria-hidden="true" />Получить отпечатки по сети</Button>
      {!props.address ? <p className="mt-2 text-xs text-slate-400">Сначала укажите адрес в форме выше.</p> : null}
      {props.fingerprints?.map((item) => <p key={`${item.algorithm}-${item.fingerprint}`} className="mt-2 break-all font-mono text-xs leading-6 text-slate-300">{item.algorithm}: {item.fingerprint}</p>)}
    </details>
    {props.message && !props.trusted ? <p className="mt-3 text-sm leading-6 text-slate-300">{props.message}</p> : null}
  </details>;
}
