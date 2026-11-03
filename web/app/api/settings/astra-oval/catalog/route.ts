import { NextResponse } from "next/server";
import { readOfficialAstraOvalCatalog } from "@/lib/astra-oval-official-catalog";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 15;

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
    return NextResponse.json({
      ok: false,
      message: "Не удалось получить метаданные официального каталога Astra. Используйте ручную настройку; источник не был изменён.",
    }, { status: 502, headers: { "Cache-Control": "no-store" } });
  }
}
