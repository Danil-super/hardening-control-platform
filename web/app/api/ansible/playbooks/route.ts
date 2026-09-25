import { NextResponse } from "next/server";
import { createCustomPlaybook, customPlaybookAuthoringEnabled, customPlaybookCapabilities, listRegisteredPlaybooks, playbookTemplates } from "@/lib/playbook-registry";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const customPlaybooks = customPlaybookCapabilities();
  return NextResponse.json({
    ok: true,
    playbooks: listRegisteredPlaybooks(),
    customPlaybooks,
    // Kept for older clients; this now controls writing drafts, not execution.
    customPlaybooksEnabled: customPlaybooks.authoringEnabled,
    templates: customPlaybooks.authoringEnabled
      ? playbookTemplates.map(({ id, title, description, kind, variables }) => ({ id, title, description, kind, variables }))
      : [],
  });
}

export async function POST(request: Request) {
  if (!customPlaybookAuthoringEnabled()) {
    return NextResponse.json({ ok: false, message: customPlaybookCapabilities().reason }, { status: 403 });
  }
  const body = await request.json().catch(() => ({}));
  try {
    const playbook = createCustomPlaybook({
      id: String(body?.id ?? "").trim(),
      title: String(body?.title ?? "").trim(),
      templateId: String(body?.templateId ?? "").trim(),
    });
    return NextResponse.json({ ok: true, playbook });
  } catch (error) {
    return NextResponse.json(
      { ok: false, message: error instanceof Error ? error.message : "Не удалось создать playbook." },
      { status: 400 },
    );
  }
}
