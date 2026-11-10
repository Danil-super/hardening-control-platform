import { cookies } from "next/headers";
import { authCookieName, isAuthConfigured, isValidSessionToken } from "@/lib/auth";
import { getReportsDir } from "@/lib/ansible-reports";
import { NativeExportError, nativeExportSecurityHeaders, nativeReportDownload, type NativeExportFormat } from "@/lib/astra-oval-native-export";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 120;

export async function GET(request: Request, { params }: { params: Promise<{ reportId: string }> }) {
  // Also enforce authentication here, independently of the normal /api/ansible proxy.
  if (!isValidSessionToken((await cookies()).get(authCookieName)?.value)) {
    return Response.json({ ok: false, error: "auth_required", message: "Требуется вход администратора." }, {
      status: isAuthConfigured() ? 401 : 503, headers: nativeExportSecurityHeaders,
    });
  }
  try {
    const { reportId } = await params;
    const query = new URL(request.url).searchParams;
    const format = query.get("format");
    if (query.has("view") && query.get("view") !== "1") throw new NativeExportError("bad_view", "Неизвестный режим просмотра.", 400);
    return await nativeReportDownload(getReportsDir(), reportId, format as NativeExportFormat | null, request.signal, query.get("view") === "1");
  } catch (error) {
    const failure = error instanceof NativeExportError ? error : new NativeExportError("native_export_failed", "Не удалось выгрузить исходный отчёт.", 503);
    return Response.json({ ok: false, error: failure.code, message: failure.message }, { status: failure.status, headers: nativeExportSecurityHeaders });
  }
}
