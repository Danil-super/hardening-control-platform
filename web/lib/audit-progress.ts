import { AsyncLocalStorage } from 'node:async_hooks';

// Server-owned callbacks: neither a request parameter nor child stdout can select a job.
const progress = new AsyncLocalStorage<(phase: string) => void>();
const phases = { prepare: 'Подготовка проверки', scan: 'Выполняется проверка хоста', report: 'Сохранение и проверка отчёта' } as const;
export function withAuditProgress<T>(update: (phase: string) => void, work: () => Promise<T>) {
  return progress.run(update, work);
}
export function reportAuditProgress(phase: keyof typeof phases) {
  try { progress.getStore()?.(phases[phase]); }
  catch { console.warn('audit_progress_update_failed'); } // Progress must not prevent evidence publication or cleanup.
}
