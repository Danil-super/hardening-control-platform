import { after, NextResponse } from "next/server";
import { resolveAstraOvalPolicyForHost } from "@/lib/astra-oval-policy";
import { ovalPreparationStatus, startOvalPreparation } from "@/lib/astra-oval-preparation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 1600;

export async function GET(request: Request) {
  try {
    const alias = new URL(request.url).searchParams.get("alias") ?? "";
    const policy = resolveAstraOvalPolicyForHost(alias);
    return NextResponse.json({ ok: true, alias, group: policy.groupName, source: { mode: policy.config.mode, url: policy.config.url, path: policy.config.path, sha256: policy.config.sha256, releasePattern: policy.config.releasePattern }, preparation: ovalPreparationStatus(policy.config) }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) { return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось проверить источник." }, { status: 400 }); }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (typeof body?.alias !== "string") throw new Error("Выберите хост.");
    const policy = resolveAstraOvalPolicyForHost(body.alias);
    const started = startOvalPreparation(policy.config);
    if (started.run) after(started.run);
    return NextResponse.json({ ok: true, alias: body.alias, preparation: started.status }, { status: started.run ? 202 : 200 });
  } catch (error) { return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Подготовка базы не запущена." }, { status: 400 }); }
}
