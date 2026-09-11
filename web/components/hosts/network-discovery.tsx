"use client";

import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { NetworkCandidate } from "@/lib/network-discovery";

export type DiscoveryPayload = {
  ok?: boolean; defaultCidr?: string; candidates?: NetworkCandidate[];
  found?: Array<{ ip: string; sshOpen: boolean; alias: string; methods: string[] }>;
  message?: string;
};

export function NetworkDiscovery({ cidr, result, loading, onCidr, onDetect, onScan, onChoose }: {
  cidr: string; result: DiscoveryPayload | null; loading: string;
  onCidr: (value: string) => void; onDetect: () => void; onScan: () => void;
  onChoose: (ip: string, alias: string) => void;
}) {
  const sshHosts = result?.found?.filter((host) => host.sshOpen) ?? [];
  return <section id="network-discovery" className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 sm:p-5" aria-labelledby="network-discovery-title">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="network-discovery-title" className="text-lg font-semibold text-white">1. Сканирование сети</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">Найдите машины с открытым SSH-портом 22 в своей подсети. Если адрес уже известен, переходите к подключению SSH ниже.</p>
      </div>
      <a href="#host-form" className="text-sm text-sky-300 underline underline-offset-4">Адрес уже известен</a>
    </div>
    <div className="mt-4 flex flex-wrap items-end gap-3">
      <label className="block min-w-0 text-sm text-slate-300">Подсеть целевых хостов
        <input value={cidr} onChange={(event) => onCidr(event.target.value)} placeholder="192.168.1.0/24" spellCheck={false} disabled={Boolean(loading)}
          className="mt-2 block h-11 w-64 max-w-full rounded-lg border border-slate-700 bg-slate-900 px-3 text-slate-100 focus:border-sky-300 focus:outline-none" />
      </label>
      <Button variant="secondary" onClick={onDetect} disabled={Boolean(loading)}><Search size={16} className={loading === "detect" ? "animate-pulse" : ""} aria-hidden="true" />{loading === "detect" ? "Определяем…" : "Подставить подсеть"}</Button>
      <Button onClick={onScan} disabled={Boolean(loading) || !cidr.trim()}><Search size={16} className={loading === "scan" ? "animate-pulse" : ""} aria-hidden="true" />{loading === "scan" ? "Ищем хосты…" : "Найти SSH-хосты"}</Button>
    </div>
    <p className="mt-3 text-xs leading-5 text-slate-400">Разрешены приватные диапазоны /24–/30, до 254 адресов. Сканирование выполняется с Ubuntu и ничего не добавляет автоматически. Другой SSH-порт укажите при ручном добавлении.</p>
    {result?.message ? <p className="mt-3 text-sm leading-6 text-slate-300" role="status">{result.message}</p> : null}
    {result?.candidates?.length ? <div className="mt-3 flex flex-wrap gap-2">
      {result.candidates.map((candidate) => <button type="button" key={candidate.cidr} disabled={Boolean(loading)} onClick={() => onCidr(candidate.cidr)} title={candidate.label}
        className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-left text-xs text-slate-300 disabled:opacity-50">
        <span className="font-mono text-sky-200">{candidate.cidr}</span>{candidate.device ? ` · ${candidate.device}` : ""}
        <span className="mt-1 block">{candidate.label}</span>
      </button>)}
    </div> : null}
    {result?.found ? <div className="mt-4 border-t border-slate-800 pt-4">
      <p className="text-sm text-slate-300">{sshHosts.length ? `Найдено SSH-хостов: ${sshHosts.length}. Выберите адрес — он появится в форме добавления.` : "Хосты с открытым SSH-портом 22 не найдены. Проверьте подсеть, доступность сети с Ubuntu и порт SSH."}</p>
      <div className="mt-3 flex flex-wrap gap-2">{sshHosts.map((host) => <Button key={host.ip} variant="secondary" disabled={Boolean(loading)} onClick={() => onChoose(host.ip, host.alias)}>{host.ip} → В форму</Button>)}</div>
    </div> : null}
  </section>;
}
