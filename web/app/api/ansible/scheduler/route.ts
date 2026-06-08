import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import {
  appendIncident,
  getRepoRoot,
  isPlaybookAction,
  isSafeLimit,
  normalizeProfileId,
  playbooks,
  runAnsiblePlaybook,
  type PlaybookAction,
} from "@/lib/ansible-control";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type SchedulerState = {
  enabled: boolean;
  action: PlaybookAction;
  intervalMinutes: number;
  profileId: string;
  limit: string | null;
  lastRunAt: string | null;
  nextRunAt: string | null;
  running: boolean;
};

const defaultState: SchedulerState = {
  enabled: false,
  action: "agentlessAudit",
  intervalMinutes: 15,
  profileId: "basic_linux",
  limit: null,
  lastRunAt: null,
  nextRunAt: null,
  running: false,
};

type SchedulerGlobal = typeof globalThis & {
  hcpScheduler?: {
    timer?: ReturnType<typeof setInterval>;
    state: SchedulerState;
  };
};

function getSchedulerPath() {
  return path.join(getRepoRoot(), "ansible", "scheduler.json");
}

function readSavedState() {
  const schedulerPath = getSchedulerPath();
  if (!existsSync(schedulerPath)) {
    return defaultState;
  }
  try {
    return { ...defaultState, ...JSON.parse(readFileSync(schedulerPath, "utf8")) } as SchedulerState;
  } catch {
    return defaultState;
  }
}

function writeSavedState(state: SchedulerState) {
  writeFileSync(getSchedulerPath(), JSON.stringify(state, null, 2));
}

function getScheduler() {
  const globalRef = globalThis as SchedulerGlobal;
  if (!globalRef.hcpScheduler) {
    globalRef.hcpScheduler = { state: readSavedState() };
  }
  return globalRef.hcpScheduler;
}

function stopTimer() {
  const scheduler = getScheduler();
  if (scheduler.timer) {
    clearInterval(scheduler.timer);
    scheduler.timer = undefined;
  }
}

async function executeScheduledRun() {
  const scheduler = getScheduler();
  const state = scheduler.state;
  if (!state.enabled || state.running) {
    return;
  }

  state.running = true;
  writeSavedState(state);
  try {
    const { command, repoRoot } = await runAnsiblePlaybook({
      action: state.action,
      profileId: state.profileId,
      limit: state.limit ?? undefined,
    });
    state.lastRunAt = new Date().toISOString();
    appendIncident({
      action: state.action,
      kind: "audit",
      status: "success",
      profileId: state.profileId,
      limit: state.limit,
      message: "Плановая проверка выполнена.",
      command,
    }, repoRoot);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Плановая проверка завершилась с ошибкой.";
    appendIncident({
      action: state.action,
      kind: "audit",
      status: "failed",
      profileId: state.profileId,
      limit: state.limit,
      message,
    });
  } finally {
    state.running = false;
    state.nextRunAt = new Date(Date.now() + state.intervalMinutes * 60_000).toISOString();
    writeSavedState(state);
  }
}

function startTimer() {
  const scheduler = getScheduler();
  stopTimer();
  if (!scheduler.state.enabled) {
    return;
  }
  scheduler.state.nextRunAt = new Date(Date.now() + scheduler.state.intervalMinutes * 60_000).toISOString();
  writeSavedState(scheduler.state);
  scheduler.timer = setInterval(() => {
    void executeScheduledRun();
  }, scheduler.state.intervalMinutes * 60_000);
}

export async function GET() {
  const scheduler = getScheduler();
  return NextResponse.json({ ok: true, state: scheduler.state, active: Boolean(scheduler.timer) });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const action = body?.action;
  const intervalMinutes = Number(body?.intervalMinutes);
  const limit = body?.limit;

  if (!isPlaybookAction(action) || playbooks[action].kind !== "audit") {
    return NextResponse.json(
      { ok: false, error: "bad_action", message: "Планировщик поддерживает только audit-playbook'и." },
      { status: 400 },
    );
  }

  if (!Number.isInteger(intervalMinutes) || ![5, 15, 30, 60].includes(intervalMinutes)) {
    return NextResponse.json(
      { ok: false, error: "bad_interval", message: "Интервал должен быть 5, 15, 30 или 60 минут." },
      { status: 400 },
    );
  }

  if (limit && !isSafeLimit(limit)) {
    return NextResponse.json(
      { ok: false, error: "bad_limit", message: "Limit может содержать только имена хостов/групп без пробелов." },
      { status: 400 },
    );
  }

  const scheduler = getScheduler();
  scheduler.state = {
    ...scheduler.state,
    enabled: Boolean(body?.enabled),
    action,
    intervalMinutes,
    profileId: normalizeProfileId(body?.profileId),
    limit: limit || null,
    nextRunAt: null,
  };
  writeSavedState(scheduler.state);
  startTimer();

  return NextResponse.json({ ok: true, state: scheduler.state, active: Boolean(scheduler.timer) });
}
