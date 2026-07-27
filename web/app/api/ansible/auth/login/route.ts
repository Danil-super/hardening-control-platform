import { NextResponse } from "next/server";
import { authCookieName, createSessionToken, isAuthConfigured, isValidPassword } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));

  if (!isAuthConfigured()) {
    return NextResponse.json(
      {
        ok: false,
        error: "auth_not_configured",
        message: "Задайте HCP_ADMIN_PASSWORD в web/.env.local и перезапустите сайт.",
      },
      { status: 503 },
    );
  }

  if (!isValidPassword(body?.password)) {
    return NextResponse.json(
      { ok: false, error: "bad_password", message: "Неверный пароль администратора." },
      { status: 401 },
    );
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set({
    name: authCookieName,
    value: createSessionToken(),
    httpOnly: true,
    sameSite: "lax",
    secure: new URL(request.url).protocol === "https:",
    path: "/",
    maxAge: 60 * 60 * 8,
  });

  return response;
}
