import { NextResponse } from "next/server";
import { getControlPublicKey, isSafeSshHostAddress, normalizeSshPort, scanHostKeys, trustHostKey } from "@/lib/ssh-access";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function errorResponse(error: unknown, fallback: string) {
  const reason = error as { message?: string; code?: string };
  return NextResponse.json(
    { ok: false, error: reason.code ?? "access_setup_failed", message: reason.message ?? fallback },
    { status: 400 },
  );
}

export async function GET() {
  try {
    const key = await getControlPublicKey();
    return NextResponse.json({ ok: true, ...key });
  } catch (error) {
    return errorResponse(error, "Не удалось получить публичный ключ узла управления.");
  }
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  const operation = body?.operation;
  const address = typeof body?.address === "string" ? body.address.trim() : "";
  const port = normalizeSshPort(body?.port);
  if (!isSafeSshHostAddress(address)) {
    return NextResponse.json({ ok: false, error: "bad_address", message: "Укажите корректный IP-адрес или hostname." }, { status: 400 });
  }

  try {
    if (operation === "scan") {
      const candidates = await scanHostKeys(address, port);
      return NextResponse.json({
        ok: true,
        fingerprints: candidates.map(({ fingerprint, algorithm }) => ({ fingerprint, algorithm })),
        message: "Fingerprint получен по сети и пока не является доверенным. Сверьте его через консоль или доверенный канал.",
      });
    }
    if (operation === "trust") {
      const expectedFingerprint = typeof body?.expectedFingerprint === "string" ? body.expectedFingerprint.trim() : "";
      if (!/^SHA256:[A-Za-z0-9+/=]{16,}$/.test(expectedFingerprint)) {
        return NextResponse.json({ ok: false, error: "bad_fingerprint", message: "Вставьте fingerprint формата SHA256:… из доверенного источника." }, { status: 400 });
      }
      const trusted = await trustHostKey({ address, port, expectedFingerprint });
      return NextResponse.json({
        ok: true,
        ...trusted,
        message: trusted.alreadyTrusted ? "Этот SSH key уже был доверенным." : "SSH host key сохранён. Теперь можно выполнить проверку подключения.",
      });
    }
    return NextResponse.json({ ok: false, error: "bad_operation", message: "Неизвестная операция мастера подключения." }, { status: 400 });
  } catch (error) {
    return errorResponse(error, "Не удалось подготовить SSH-доступ.");
  }
}
