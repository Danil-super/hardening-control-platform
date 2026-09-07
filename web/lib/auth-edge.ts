export const authCookieName = "hcp_admin_session";

function bytesToHex(bytes: ArrayBuffer) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function isProtectedPath(pathname: string) {
  return (
    pathname === "/hosts" ||
    pathname === "/data-sources" ||
    pathname === "/policies" ||
    pathname === "/playbooks" ||
    pathname.startsWith("/reports/agentless") ||
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

export async function createEdgeSessionToken() {
  const password = process.env.HCP_ADMIN_PASSWORD?.trim() || "";
  const secret = process.env.HCP_AUTH_SECRET?.trim() || password;
  if (!password || !secret) {
    return "";
  }

  const input = new TextEncoder().encode(`${password}:${secret}`);
  return bytesToHex(await crypto.subtle.digest("SHA-256", input));
}
