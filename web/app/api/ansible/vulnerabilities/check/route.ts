import { NextResponse } from "next/server";
import { scanPackageInventory } from "@/lib/vulnerability-scan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  try {
    const result = await scanPackageInventory({
      hostAlias: typeof body?.hostAlias === "string" ? body.hostAlias.trim() : undefined,
      reportId: typeof body?.reportId === "string" ? body.reportId.trim() : undefined,
    });
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        message: error instanceof Error ? error.message : "Не удалось выполнить CVE-аудит пакетов.",
      },
      { status: 400 },
    );
  }
}
