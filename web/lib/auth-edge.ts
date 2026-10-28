export function isProtectedPath(pathname: string) {
  return (
    pathname === "/hosts" ||
    pathname === "/data-sources" ||
    pathname === "/policies" ||
    pathname === "/playbooks" ||
    pathname.startsWith("/reports/agentless") ||
    pathname.startsWith("/reports/correlation") ||
    (pathname.startsWith("/api/ansible") && !pathname.startsWith("/api/ansible/auth")) ||
    pathname.startsWith("/api/settings")
  );
}

export function isMutatingRequest(method: string) {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

export function hasTrustedOrigin(request: {
  headers: Headers;
  nextUrl: { origin: string };
}) {
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  const forwardedProtocol = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim();
  const expectedOrigin = host
    ? `${forwardedProtocol ?? new URL(request.nextUrl.origin).protocol.replace(/:$/, "")}://${host}`
    : request.nextUrl.origin;
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  if (origin) {
    return origin === expectedOrigin;
  }
  if (referer) {
    try {
      return new URL(referer).origin === expectedOrigin;
    } catch {
      return false;
    }
  }
  return false;
}
