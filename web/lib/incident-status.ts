import type { IncidentRecord } from '@/lib/state-store';
// Earlier versions recorded completed partial audits as failures. Interpret
// only the explicit completion marker; never rewrite the signed journal.
export function incidentDisplayStatus(incident: Pick<IncidentRecord, 'status' | 'kind' | 'message'>) {
  if (incident.kind === 'audit' && incident.status === 'failed' && incident.message.startsWith('Проверка выполнена. Проверка неполная:')) return 'partial';
  return incident.status;
}
