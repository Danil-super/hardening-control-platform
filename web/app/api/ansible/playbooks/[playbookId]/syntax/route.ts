import { NextResponse } from "next/server";
import { getRegisteredPlaybook, syntaxCheckPlaybook } from "@/lib/playbook-registry";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ playbookId: string }> },
) {
  const { playbookId } = await params;
  const playbook = getRegisteredPlaybook(decodeURIComponent(playbookId));
  if (!playbook) {
    return NextResponse.json({ ok: false, message: "Playbook не найден." }, { status: 404 });
  }

  try {
    const { stdout, stderr } = await syntaxCheckPlaybook(playbook);
    return NextResponse.json({ ok: true, stdout, stderr });
  } catch (error) {
    const output = error as { stdout?: string; stderr?: string; message?: string };
    return NextResponse.json(
      {
        ok: false,
        message: output.message ?? "Syntax-check завершился с ошибкой.",
        stdout: output.stdout ?? "",
        stderr: output.stderr ?? "",
      },
      { status: 400 },
    );
  }
}
