import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { authCookieName, revokeSessionToken } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request: Request) {
  revokeSessionToken((await cookies()).get(authCookieName)?.value);
  const response = NextResponse.json({ ok: true });
  response.cookies.set({
    name: authCookieName,
    value: "",
    httpOnly: true,
    sameSite: "lax",
    secure: new URL(request.url).protocol === "https:",
    path: "/",
    maxAge: 0,
  });

  return response;
}
