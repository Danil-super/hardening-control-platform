import { after, NextResponse } from 'next/server';
import { createHash } from 'node:crypto';
import { POST as executeAudit } from '@/app/api/ansible/run/route';
import { POST as checkVulnerabilities } from '@/app/api/ansible/vulnerabilities/check/route';
import { POST as syncDependencyTrack } from '@/app/api/ansible/dependency-track/sync/route';
import { isPlaybookAction, playbooks, normalizeProfileId, inventoryHostExists } from '@/lib/ansible-control';
import { createAuditJob, listAuditJobs, setAuditJobPhase, finishAuditJob } from '@/lib/state-store';
import { credentialTransportAllowed } from '@/lib/ssh-bootstrap';
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export const maxDuration = 2700;
export async function GET() { return NextResponse.json({ ok: true, jobs: listAuditJobs() }); }
export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  const action: unknown = body?.action;
  if (!body || !isPlaybookAction(action) || playbooks[action].kind !== 'audit'
      || ('internal' in playbooks[action] && playbooks[action].internal)) {
    return NextResponse.json({ ok: false, message: 'Выберите доступный тест аудита.' }, { status: 400 });
  }
  const hostAlias = typeof body.limit === 'string' ? body.limit.trim() : '';
  if (!hostAlias || !inventoryHostExists(hostAlias)) {
    return NextResponse.json({ ok: false, message: 'Выберите конкретный хост из inventory.' }, { status: 400 });
  }
  if (body.sudoPassword && !credentialTransportAllowed(request)) {
    return NextResponse.json({ ok: false, message: 'Для пароля sudo используйте HTTPS либо localhost.' }, { status: 400 });
  }
  if (body.sudoPassword !== undefined && (typeof body.sudoPassword !== 'string' || body.sudoPassword.length > 1024 || /[\r\n\0]/.test(body.sudoPassword))) {
    return NextResponse.json({ ok: false, message: 'Некорректный пароль sudo.' }, { status: 400 });
  }
  const profileId = normalizeProfileId(body.profileId);
  const requestKey = createHash('sha256').update(JSON.stringify({ action: body.action, profileId, hostAlias, extraVars: body.extraVars ?? {} })).digest('hex');
  const queued = createAuditJob({ action: body.action, hostAlias, profileId, requestKey });
  if (!queued.created) return NextResponse.json({ ok: queued.matches, job: queued.job,
    message: queued.matches ? 'Эта проверка уже выполняется.' : 'На этом хосте уже выполняется другая проверка.' }, { status: queued.matches ? 202 : 409 });
  // Credentials live only in this callback's memory. after() is supported by
  // the self-hosted Node server and continues after navigation/disconnection.
  const makeRequest = (payload: unknown) => new Request(request.url, { method: 'POST', headers: request.headers, body: JSON.stringify(payload) });
  after(async () => {
    try {
      setAuditJobPhase(queued.job.id, 'Выполняется проверка хоста');
      let result = await (await executeAudit(makeRequest(body))).json();
      delete body.sudoPassword;
      if (result.ok && body.action === 'packageInventory') {
        setAuditJobPhase(queued.job.id, 'Проверяются пакеты и CVE');
        result = await (await checkVulnerabilities(makeRequest({ hostAlias, reportId: result.reportId }))).json();
        if (result.ok && !result.partial && result.reportId && result.report?.vulnerabilityScan?.sbomFile) {
          setAuditJobPhase(queued.job.id, 'Передаётся SBOM в Dependency-Track');
          const synced = await (await syncDependencyTrack(makeRequest({ hostAlias, vulnerabilityReportId: result.reportId }))).json();
          if (!synced.ok) result.partial = true;
          if (synced.configured || !synced.ok) result.message = `${result.message ?? ''} ${synced.message ?? ''}`.trim();
        }
      }
      finishAuditJob(queued.job.id, { ...result, action: body.action });
    } catch {
      // Do not persist exception text, which can contain request credentials.
      finishAuditJob(queued.job.id, { ok: false, action: body.action, message: 'Проверка не завершена. Подробности доступны в журнале действий.' });
    } finally { delete body.sudoPassword; }
  });
  return NextResponse.json({ ok: true, job: queued.job }, { status: 202 });
}
