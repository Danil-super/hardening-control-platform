import { NextResponse, type NextRequest } from "next/server";
import { authCookieName, createEdgeSessionToken, hasTrustedOrigin, isMutatingRequest, isProtectedPath } from "@/lib/auth-edge";

export async function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const isProtectedApi = (
    (pathname.startsWith("/api/ansible") && !pathname.startsWith("/api/ansible/auth"))
    || pathname.startsWith("/api/settings")
  );
  if (!isProtectedPath(pathname)) {
    return NextResponse.next();
  }

  const expectedToken = await createEdgeSessionToken();
  const currentToken = request.cookies.get(authCookieName)?.value;
  if (expectedToken && currentToken === expectedToken) {
    if (
      isProtectedApi &&
      isMutatingRequest(request.method) &&
      !hasTrustedOrigin(request)
    ) {
      return NextResponse.json(
        {
          ok: false,
          error: "bad_origin",
          message: "Управляющий запрос отклонен: origin не совпадает с адресом панели.",
        },
        { status: 403 },
      );
    }
    return NextResponse.next();
  }

  if (isProtectedApi) {
    return NextResponse.json(
      {
        ok: false,
        error: expectedToken ? "auth_required" : "auth_not_configured",
        message: expectedToken
          ? "Требуется вход администратора."
          : "Задайте HCP_ADMIN_PASSWORD в web/.env.local и перезапустите сайт.",
      },
      { status: expectedToken ? 401 : 503 },
    );
  }

  const loginUrl = request.nextUrl.clone();
  loginUrl.pathname = "/login";
  loginUrl.searchParams.set("next", `${pathname}${search}`);
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ["/hosts", "/data-sources", "/policies", "/playbooks", "/reports/agentless/:path*", "/reports/correlation/:path*", "/api/ansible/:path*", "/api/settings/:path*"],
};
