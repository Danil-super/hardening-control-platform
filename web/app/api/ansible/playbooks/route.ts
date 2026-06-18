import { NextResponse } from "next/server";
import { createCustomPlaybook, listRegisteredPlaybooks, playbookTemplates } from "@/lib/playbook-registry";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  return NextResponse.json({
    ok: true,
    playbooks: listRegisteredPlaybooks(),
    templates: playbookTemplates.map(({ id, title, description, kind, variables }) => ({ id, title, description, kind, variables })),
  });
}

export async function POST(request: Request) {
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
