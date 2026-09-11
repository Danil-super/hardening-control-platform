import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

// /api/ansible/session is protected by the same proxy as hosts and audit APIs.
export function GET() {
  return NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
}
