import { NextResponse } from "next/server";
import { addCorrelatedFindingToPlan, remediationPlanForHost } from "@/lib/remediation-plan";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function safeAlias(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,96}$/.test(value);
}

function failure(error: unknown, status = 400) {
  return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось обработать план устранения." }, { status });
}

export async function GET(request: Request) {
  try {
    const hostAlias = new URL(request.url).searchParams.get("hostAlias") ?? "";
    if (!safeAlias(hostAlias)) return failure(new Error("Выберите корректный хост."));
    return NextResponse.json({ ok: true, hostAlias, ...remediationPlanForHost(hostAlias) });
  } catch (error) { return failure(error); }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    if (!safeAlias(body?.hostAlias) || typeof body?.findingKey !== "string") return failure(new Error("Выберите хост и свежую находку."));
    const item = addCorrelatedFindingToPlan(body.hostAlias, body.findingKey);
    if (!item) throw new Error("Не удалось сохранить пункт плана устранения.");
    return NextResponse.json({ ok: true, item, message: item.status === "discovered" ? "Находка добавлена в план устранения." : "Для этой находки уже есть незавершённый пункт плана." });
  } catch (error) { return failure(error); }
}
