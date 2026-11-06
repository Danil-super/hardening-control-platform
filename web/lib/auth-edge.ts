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
  // The same explicit proxy boundary used for credential transport applies here.
  // A directly connected client must not choose the authority we trust.
  const trustedProxy = process.env.HCP_TRUSTED_TLS_PROXY === "true";
  const host = (trustedProxy ? request.headers.get("x-forwarded-host") : null)
    ?? request.headers.get("host");
  const forwardedProtocol = trustedProxy ? request.headers.get("x-forwarded-proto") : null;
  let expectedOrigin: string;
  try {
    const url = new URL(request.nextUrl.origin);
    // HCP's production `next start` listener is HTTP; TLS terminates at the
    // explicitly trusted proxy. Next can already have copied forwarded proto
    // into nextUrl, so that URL cannot prove the listener's transport.
    const directProtocol = process.env.NODE_ENV === "production" ? "http" : url.protocol.replace(/:$/, "");
    const protocol = trustedProxy ? forwardedProtocol ?? url.protocol.replace(/:$/, "") : directProtocol;
    const authority = host ?? url.host;
    if (!["http", "https"].includes(protocol) || !authority || /[\s,/@\\?#]/.test(authority)) return false;
    expectedOrigin = new URL(`${protocol}://${authority}`).origin;
  } catch {
    return false;
  }
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
