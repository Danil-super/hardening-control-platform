import { after, NextResponse } from "next/server";
import { readOfficialAstraOvalCatalog } from "@/lib/astra-oval-official-catalog";
import { listInventoryGroups } from "@/lib/openscap-policy";
import { listAstraOvalPolicies, upsertAstraOvalPolicy } from "@/lib/state-store";
import { startOvalPreparation } from "@/lib/astra-oval-preparation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 1600;

const unavailable = () => NextResponse.json({
  ok: false,
  message: "Не удалось связаться с сервером Astra. Проверьте доступ в интернет, VPN или прокси и повторите обновление. Сохранённый источник не изменён.",
}, { status: 502, headers: { "Cache-Control": "no-store" } });

export async function GET(request: Request) {
  const url = new URL(request.url);
  const release = url.searchParams.get("release");
  if (!release || [...url.searchParams.keys()].some(key => key !== "release")
    || url.searchParams.getAll("release").length !== 1
    || !["1.7", "1.8"].includes(release)) {
    return NextResponse.json({ ok: false, message: "Выберите поддерживаемый каталог Astra 1.7 или 1.8." },
      { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  try {
    const preview = await readOfficialAstraOvalCatalog(release);
    return NextResponse.json({ ok: true, preview }, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    // Avoid surfacing internal network details and upstream payloads in UI.
    return unavailable();
  }
}

export async function POST(request: Request) {
  let body;
  try { body = await request.json(); } catch {
    return NextResponse.json({ ok: false, message: "Выберите группу и выпуск Astra." }, { status: 400 });
  }
  const groupName = typeof body?.groupName === "string" ? body.groupName.trim() : "";
  if (!["1.7", "1.8"].includes(body?.release) || !listInventoryGroups().includes(groupName)) {
    return NextResponse.json({ ok: false, message: "Выберите существующую группу и выпуск Astra 1.7 или 1.8." }, { status: 400 });
  }
  let preview;
  try { preview = await readOfficialAstraOvalCatalog(body.release); } catch { return unavailable(); }
  const existing = listAstraOvalPolicies().find(policy => policy.groupName === groupName);
  let policy;
  try { policy = upsertAstraOvalPolicy(groupName, {
    mode: "online", path: "", url: preview.url, sha256: preview.sha256,
    releasePattern: body.release + ".*", architectures: ["x86_64"], maxAgeDays: existing?.config.maxAgeDays ?? 30,
    sourceName: preview.sourceName, sourceReference: preview.sourceReference,
    sourceReviewedAt: null, evidenceProjection: existing?.config.evidenceProjection ?? "bounded",
  }); } catch {
    return NextResponse.json({ ok: false, message: "Не удалось сохранить источник Astra. Проверьте настройки группы." }, { status: 400 });
  }
  try {
    const started = startOvalPreparation(policy.config);
    if (started.run) after(started.run);
    return NextResponse.json({ ok: true, policy, preparation: started.status,
      message: started.status.state === "ready" ? "База Astra актуальна и готова к проверке хостов." : "Источник сохранён. База Astra загружается и проверяется на управляющей машине.",
    }, { status: started.run ? 202 : 200, headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ ok: false, sourceSaved: true, policy,
      message: "Источник сохранён, но подготовка базы не началась. Проверьте состояние баз ниже и повторите обновление.",
    }, { status: 409, headers: { "Cache-Control": "no-store" } });
  }
}
