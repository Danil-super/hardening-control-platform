import { NextResponse } from "next/server";
import { getControlPublicKey, hasSavedHostKey, isSafeSshHostAddress, normalizeSshPort, scanHostKeys, trustHostKey } from "@/lib/ssh-access";

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
  if (port === null) {
    return NextResponse.json({ ok: false, error: "bad_port", message: "SSH-порт должен быть целым числом от 1 до 65535." }, { status: 400 });
  }
  if (!isSafeSshHostAddress(address)) {
    return NextResponse.json({ ok: false, error: "bad_address", message: "Укажите корректный IP-адрес или hostname." }, { status: 400 });
  }

  try {
    if (operation === "status") {
      const trusted = await hasSavedHostKey(address, port);
      return NextResponse.json({ ok: true, trusted,
        message: trusted ? "Ключ сервера уже сохранён." : "Подтвердите сервер перед первым входом. Пароль ему ещё не передан." },
        { headers: { "Cache-Control": "no-store" } });
    }
    if (operation === "scan") {
      const candidates = await scanHostKeys(address, port);
      return NextResponse.json({
        ok: true,
        fingerprints: candidates.map(({ fingerprint, algorithm }) => ({ fingerprint, algorithm })),
        message: "Это отпечатки целевого сервера, полученные по сети. Для сверки возьмите отпечаток той же Astra из её консоли или доверенного реестра.",
      });
    }
    if (operation === "trust") {
      const expectedFingerprint = typeof body?.expectedFingerprint === "string" ? body.expectedFingerprint.trim() : "";
      if (!/^SHA256:[A-Za-z0-9+/=]{16,}$/.test(expectedFingerprint)) {
        return NextResponse.json({ ok: false, error: "bad_fingerprint", message: "Скопируйте одно значение SHA256:… из консоли целевой Astra или доверенного реестра, без пробелов и остальной строки." }, { status: 400 });
      }
      const trusted = await trustHostKey({ address, port, expectedFingerprint });
      return NextResponse.json({
        ok: true,
        ...trusted,
        message: trusted.alreadyTrusted ? "Отпечаток совпал с уже сохранённым ключом сервера. Продолжите подключение." : "Отпечаток из доверенного источника совпал с ключом сервера по сети. Ключ сохранён; нажмите «Подключить хост» или «Сохранить подключение».",
      });
    }
    return NextResponse.json({ ok: false, error: "bad_operation", message: "Неизвестная операция мастера подключения." }, { status: 400 });
  } catch (error) {
    return errorResponse(error, "Не удалось подготовить SSH-доступ.");
  }
}
