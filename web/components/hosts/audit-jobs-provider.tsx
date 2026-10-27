'use client';
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { LoaderCircle, CheckCircle2, AlertTriangle } from 'lucide-react';
import type { AuditJob } from '@/lib/state-store';
import { useNotify } from '@/components/ui/feedback';
import { auditActionLabels as labels, isActiveAuditJob as active, completedAuditTransitions, auditCompletionMessage, mergeAuditSnapshot } from '@/lib/audit-job-status';
const JobsContext = createContext<{ jobs: AuditJob[]; refresh: () => Promise<void>; rememberJob: (job: AuditJob) => void; unavailable: boolean }>({ jobs: [], refresh: async () => {}, rememberJob: () => {}, unavailable: false });
export const useAuditJobs = () => useContext(JobsContext);
export function AuditJobsProvider({ children }: { children: ReactNode }) {
  const [jobs, setJobs] = useState<AuditJob[]>([]);
  const [unavailable, setUnavailable] = useState(false);
  const previous = useRef<AuditJob[]>([]);
  const pendingRefresh = useRef<Promise<void> | null>(null);
  const revision = useRef(0);
  const registered = useRef(new Map<string, { revision: number; job: AuditJob }>());
  const rememberJob = useCallback((job: AuditJob) => {
    registered.current.set(job.id, { revision: ++revision.current, job });
    previous.current = [job, ...previous.current.filter((item) => item.id !== job.id)];
    setJobs((items) => [job, ...items.filter((item) => item.id !== job.id)]);
  }, []);
  const notify = useNotify();
  const pathname = usePathname();
  const refresh = useCallback(() => {
    if (pendingRefresh.current) return pendingRefresh.current;
    const startingRevision = revision.current;
    const request = (async () => {
    try {
      const response = await fetch('/api/ansible/jobs', { cache: 'no-store' });
      if (response.status === 401) {
        previous.current = [];
        registered.current.clear();
        setJobs([]); setUnavailable(false);
        return;
      }
      if (!response.ok) throw new Error('jobs_unavailable');
      const payload = await response.json();
      const snapshot: AuditJob[] = payload.jobs;
      if (!Array.isArray(snapshot)) throw new Error('invalid_jobs');
      const next = mergeAuditSnapshot(snapshot, Array.from(registered.current.values()).filter((item) => item.revision > startingRevision).map((item) => item.job));
      for (const [id, item] of registered.current) if (item.revision <= startingRevision || snapshot.some((job) => job.id === id)) registered.current.delete(id);
      for (const job of completedAuditTransitions(previous.current, next)) {
        notify(auditCompletionMessage(job), job.status === 'completed' ? 'success' : job.status === 'partial' ? 'warning' : 'error');
      }
      previous.current = next;
      setJobs(next); setUnavailable(false);
    } catch { setUnavailable(true); }
    })();
    pendingRefresh.current = request;
    void request.finally(() => { if (pendingRefresh.current === request) pendingRefresh.current = null; });
    return request;
  }, [notify]);
  useEffect(() => {
    if (pathname === '/login') { previous.current = []; return; }
    void refresh();
    const interval = window.setInterval(() => void refresh(), 2500);
    const onFocus = () => void refresh();
    window.addEventListener('focus', onFocus);
    return () => { window.clearInterval(interval); window.removeEventListener('focus', onFocus); };
  }, [pathname, refresh]);
  return <JobsContext.Provider value={{ jobs, refresh, rememberJob, unavailable }}>{children}</JobsContext.Provider>;
}
export function AuditJobActivity() {
  const { jobs, unavailable } = useAuditJobs();
  const [now, setNow] = useState(0);
  const running = jobs.filter(active);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  if (!running.length) return unavailable ? <p role="status" className="mb-5 rounded-xl border border-amber-400/30 bg-amber-500/5 p-4 text-sm text-amber-100">Не удалось получить состояние проверок. Связь с HCP восстанавливается; не запускайте тест повторно до уточнения статуса.</p> : null;
  return <section aria-label="Выполняемые проверки" className="mb-6 space-y-3">
    {running.map(job => {
      const elapsed = Math.max(0, Math.floor(((now || Date.now()) - Date.parse(job.createdAt)) / 1000));
      return <div key={job.id} role="status" className="flex flex-wrap items-center gap-4 rounded-xl border border-sky-400/30 bg-sky-400/5 p-4">
        <LoaderCircle size={22} className="animate-spin text-sky-300" aria-hidden="true" />
        <div className="min-w-0 flex-1"><p className="font-semibold text-sky-100">{labels[job.action] ?? job.action} · {job.hostAlias}</p>
          <p className="mt-1 text-sm text-slate-300">{unavailable ? 'Связь потеряна. Последнее известное состояние: ' : ''}{job.phase}<span aria-hidden="true"> · {Math.floor(elapsed / 60)} мин {elapsed % 60} с</span></p>
          <p className="mt-1 text-xs text-slate-400">Можно переходить между страницами: проверка выполняется на сервере.</p></div>
        <Link href="/hosts" className="rounded-lg px-3 py-2 text-sm text-sky-200 underline underline-offset-4">К хосту</Link>
      </div>;
    })}
  </section>;
}
export function AuditJobHistory({ hostAlias }: { hostAlias: string }) {
  const { jobs } = useAuditJobs();
  const latest = jobs.filter(job => job.hostAlias === hostAlias && !active(job)).slice(0, 3);
  if (!latest.length) return null;
  return <section aria-label="Последние проверки" className="space-y-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
    <h3 className="font-semibold">Последние проверки</h3>
    {latest.map(job => <div key={job.id} className="flex items-start gap-3 border-t border-slate-800 pt-3">
      {job.status === 'completed' ? <CheckCircle2 size={18} className="mt-1 shrink-0 text-emerald-300" /> : <AlertTriangle size={18} className={`mt-1 shrink-0 ${job.status === 'partial' ? 'text-amber-300' : 'text-red-300'}`} />}
      <div className="min-w-0 flex-1"><p className="text-sm font-medium">{labels[job.action] ?? job.action} · {job.status === 'completed' ? 'завершена' : job.status === 'partial' ? 'частичный результат' : job.status === 'interrupted' ? 'прервана' : 'ошибка'}</p>
        <p className="mt-1 break-words text-sm text-slate-400">{job.result?.message}</p>
        {job.result?.reportId ? <Link className="mt-2 inline-block text-sm text-sky-200 underline underline-offset-4" href={`/reports/agentless/${encodeURIComponent(job.result.reportId)}`}>Открыть отчёт</Link> : null}</div>
    </div>)}
  </section>;
}
