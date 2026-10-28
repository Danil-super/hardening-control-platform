import { NextResponse, type NextRequest } from "next/server";
import { hasTrustedOrigin, isMutatingRequest, isProtectedPath } from "@/lib/auth-edge";
import { authCookieName, isAuthConfigured, isValidSessionToken } from "@/lib/auth";

export async function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const isProtectedApi = (
    (pathname.startsWith("/api/ansible") && !pathname.startsWith("/api/ansible/auth"))
    || pathname.startsWith("/api/settings")
  );
  if (!isProtectedPath(pathname)) {
    return NextResponse.next();
  }

  const configured = isAuthConfigured();
  const currentToken = request.cookies.get(authCookieName)?.value;
  if (isValidSessionToken(currentToken)) {
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
        error: configured ? "auth_required" : "auth_not_configured",
        message: configured
          ? "Требуется вход администратора."
          : "Пароль администратора не настроен. Задайте HCP_ADMIN_PASSWORD в настройках развёртывания и перезапустите платформу.",
      },
      { status: configured ? 401 : 503 },
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
