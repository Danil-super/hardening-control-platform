import { cookies } from "next/headers";
import { authCookieName, isAuthConfigured, isValidSessionToken } from "@/lib/auth";
import { renderAuditReportPdf } from "@/lib/audit-report-pdf";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 120;
let active = 0;
const headers = { "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'" };

export async function GET(_request: Request, { params }: { params: Promise<{ reportId: string }> }) {
  if (!isValidSessionToken((await cookies()).get(authCookieName)?.value)) return Response.json({ ok: false, message: "Требуется вход администратора." }, { status: isAuthConfigured() ? 401 : 503, headers });
  const { reportId } = await params;
  if (!/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,219}$/.test(reportId)) return Response.json({ ok: false, message: "Некорректный идентификатор отчёта." }, { status: 400, headers });
  if (active >= 2) return Response.json({ ok: false, message: "Формирование PDF занято. Повторите позже." }, { status: 429, headers });
  active++;
  try {
    const result = await renderAuditReportPdf(reportId);
    if (!result) return Response.json({ ok: false, message: "Отчёт не найден." }, { status: 404, headers });
    return new Response(new Uint8Array(result.pdf), { headers: { ...headers,
      "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="${result.id}-hcp.pdf"`,
      "Content-Length": String(result.pdf.length), "X-Source-SHA256": result.sourceSha256,
    } });
  } catch {
    return Response.json({ ok: false, message: "Не удалось сформировать PDF. Исходные данные не изменены; доступны отчёт на сайте и JSON HCP." }, { status: 503, headers });
  } finally { active--; }
}
