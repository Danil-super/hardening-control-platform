import { NextResponse } from "next/server";
import { listInventoryGroups } from "@/lib/openscap-policy";
import {
  deleteOpenScapException,
  deleteOpenScapPolicy,
  listOpenScapExceptions,
  listOpenScapPolicies,
  upsertOpenScapException,
  upsertOpenScapPolicy,
} from "@/lib/state-store";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function payload() {
  const now = Date.now();
  return {
    ok: true,
    inventoryGroups: listInventoryGroups(),
    policies: listOpenScapPolicies(),
    exceptions: listOpenScapExceptions().map((exception) => ({
      ...exception,
      active: Date.parse(exception.expiresAt) > now,
    })),
  };
}

function asText(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function assertKnownInventoryGroup(groupName: string) {
  if (!listInventoryGroups().includes(groupName)) {
    throw new Error("Выберите существующую группу из inventory.");
  }
}

export async function GET() {
  try { return NextResponse.json(payload()); }
  catch (error) { return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось прочитать политики." }, { status: 400 }); }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  try {
    if (body?.kind === "profile") {
      const groupName = asText(body.groupName);
      assertKnownInventoryGroup(groupName);
      const policy = upsertOpenScapPolicy({
        groupName,
        datastream: asText(body.datastream),
        profile: asText(body.profile),
      });
      return NextResponse.json({ ...payload(), message: `Профиль для группы ${policy?.groupName ?? ""} сохранён.` });
    }
    if (body?.kind === "exception") {
      const groupName = asText(body.groupName);
      assertKnownInventoryGroup(groupName);
      const exception = upsertOpenScapException({
        groupName,
        ruleId: asText(body.ruleId),
        reason: asText(body.reason),
        expiresAt: asText(body.expiresAt),
      });
      return NextResponse.json({ ...payload(), message: `Исключение ${exception?.ruleId ?? ""} сохранено.` });
    }
    return NextResponse.json({ ok: false, message: "Неизвестный тип настройки." }, { status: 400 });
  } catch (error) {
    return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось сохранить настройку." }, { status: 400 });
  }
}

export async function DELETE(request: Request) {
  const body = await request.json().catch(() => ({}));
  try {
    if (body?.kind === "profile") {
      const deleted = deleteOpenScapPolicy(asText(body.groupName));
      return NextResponse.json({ ...payload(), message: deleted ? "Профиль удалён." : "Профиль уже отсутствует." });
    }
    if (body?.kind === "exception") {
      const deleted = deleteOpenScapException(asText(body.id));
      return NextResponse.json({ ...payload(), message: deleted ? "Исключение удалено." : "Исключение уже отсутствует." });
    }
    return NextResponse.json({ ok: false, message: "Неизвестный тип настройки." }, { status: 400 });
  } catch (error) {
    return NextResponse.json({ ok: false, message: error instanceof Error ? error.message : "Не удалось удалить настройку." }, { status: 400 });
  }
}
