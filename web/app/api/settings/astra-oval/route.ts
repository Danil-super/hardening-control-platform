import { NextResponse } from "next/server";
import { listInventoryGroups } from "@/lib/openscap-policy";
import { deleteAstraOvalPolicy, listAstraOvalPolicies, upsertAstraOvalPolicy } from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
const payload = () => ({ ok: true, inventoryGroups: listInventoryGroups(), policies: listAstraOvalPolicies() });
const failure = (error: unknown) => NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось обработать настройки OVAL." }, { status: 400 });

export async function GET() {
  try { return NextResponse.json(payload()); } catch (error) { return failure(error); }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const groupName = typeof body?.groupName === "string" ? body.groupName.trim() : "";
    if (!listInventoryGroups().includes(groupName)) throw new Error("Выберите существующую группу inventory.");
    upsertAstraOvalPolicy(groupName, body.config);
    return NextResponse.json({ ...payload(), message: "Источник OVAL сохранён. Его содержимое и применимость будут проверены при аудите." });
  } catch (error) { return failure(error); }
}

export async function DELETE(request: Request) {
  try {
    const body = await request.json();
    if (typeof body?.groupName !== "string") throw new Error("Укажите группу.");
    deleteAstraOvalPolicy(body.groupName.trim());
    return NextResponse.json({ ...payload(), message: "Источник OVAL удалён." });
  } catch (error) { return failure(error); }
}
