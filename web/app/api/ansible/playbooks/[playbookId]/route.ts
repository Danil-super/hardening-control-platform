import { NextResponse } from "next/server";
import {
  deleteCustomPlaybook,
  customPlaybooksEnabled,
  getRegisteredPlaybook,
  readPlaybookContent,
  updateCustomPlaybook,
  type PlaybookVariable,
} from "@/lib/playbook-registry";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ playbookId: string }> },
) {
  const { playbookId } = await params;
  const playbook = getRegisteredPlaybook(decodeURIComponent(playbookId));
  if (!playbook) {
    return NextResponse.json({ ok: false, message: "Playbook не найден." }, { status: 404 });
  }
  if (playbook.source === "custom" && !customPlaybooksEnabled()) {
    return NextResponse.json({ ok: false, message: "Пользовательские playbook отключены в production режиме." }, { status: 403 });
  }

  return NextResponse.json({
    ok: true,
    playbook,
    content: readPlaybookContent(playbook),
  });
}

export async function PUT(
  request: Request,
  { params }: { params: Promise<{ playbookId: string }> },
) {
  const { playbookId } = await params;
  const body = await request.json().catch(() => ({}));
  const playbook = getRegisteredPlaybook(decodeURIComponent(playbookId));
  if (!playbook) {
    return NextResponse.json({ ok: false, message: "Playbook не найден." }, { status: 404 });
  }
  if (playbook.source === "custom" && !customPlaybooksEnabled()) {
    return NextResponse.json({ ok: false, message: "Пользовательские playbook отключены в production режиме." }, { status: 403 });
  }

  try {
    const variables = Array.isArray(body?.variables) ? body.variables as PlaybookVariable[] : [];
    const updated = updateCustomPlaybook({
      playbook,
      title: String(body?.title ?? playbook.title),
      kind: body?.kind === "audit" ? "audit" : "response",
      requiresLimit: Boolean(body?.requiresLimit),
      variables,
      content: String(body?.content ?? ""),
    });
    return NextResponse.json({ ok: true, playbook: updated, content: readPlaybookContent(updated) });
  } catch (error) {
    return NextResponse.json(
      { ok: false, message: error instanceof Error ? error.message : "Не удалось сохранить playbook." },
      { status: 400 },
    );
  }
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ playbookId: string }> },
) {
  const { playbookId } = await params;
  const playbook = getRegisteredPlaybook(decodeURIComponent(playbookId));
  if (!playbook) {
    return NextResponse.json({ ok: false, message: "Playbook не найден." }, { status: 404 });
  }

  try {
    deleteCustomPlaybook(playbook);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return NextResponse.json(
      { ok: false, message: error instanceof Error ? error.message : "Не удалось удалить playbook." },
      { status: 400 },
    );
  }
}
