import { NextResponse } from "next/server";
import { decommissionHost, hostCloseoutStatus, recoverHostCloseout } from "@/lib/host-closeout";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function safeAlias(value: unknown): value is string {
  return typeof value === "string" && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/.test(value) && !["all", "ungrouped", "preflight"].includes(value);
}

export async function GET(request: Request) {
  const alias = new URL(request.url).searchParams.get("alias");
  if (!safeAlias(alias)) return NextResponse.json({ ok: false, message: "Укажите корректный alias хоста." }, { status: 400 });
  try { return NextResponse.json({ ok: true, ...hostCloseoutStatus(alias) }); }
  catch { return NextResponse.json({ ok: false, message: "Не удалось прочитать состояние завершения работ." }, { status: 400 }); }
}

export async function POST(request: Request) {
  try {
    const text = await request.text();
    if (text.length > 8192) throw new Error("Слишком большой протокол завершения работ.");
    const body = JSON.parse(text);
    if (!body || typeof body !== "object" || Array.isArray(body) || !safeAlias(body.alias)) throw new Error("Укажите корректный alias хоста.");
    if (body.confirmation !== body.alias) throw new Error("Для завершения работ введите alias хоста точно как показано.");
    const result = body.recover === true
      ? recoverHostCloseout(body.alias, String(body.credentialId ?? ""), body)
      : await decommissionHost(body.alias);
    return NextResponse.json(result);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "decommission_failed";
    return NextResponse.json({ ok: false, error: code, recoveryRequired: code === "closeout_recovery_required",
      message: error instanceof Error ? error.message : "Не удалось завершить работы по хосту." },
    { status: ["operation_owner_live", "closeout_recovery_required", "host_operation_active", "recovery_version_stale", "recovery_not_available"].includes(code) ? 409 : 400 });
  }
}
