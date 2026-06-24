export const authCookieName = "hcp_admin_session";

function bytesToHex(bytes: ArrayBuffer) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function isProtectedPath(pathname: string) {
  return (
    pathname === "/hosts" ||
    pathname === "/playbooks" ||
    pathname.startsWith("/reports/agentless") ||
    (pathname.startsWith("/api/ansible") && !pathname.startsWith("/api/ansible/auth"))
  );
}

export function isMutatingRequest(method: string) {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

export function hasTrustedOrigin(request: {
  headers: Headers;
  nextUrl: { origin: string };
}) {
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  if (origin) {
    return origin === request.nextUrl.origin;
  }
  if (referer) {
    try {
      return new URL(referer).origin === request.nextUrl.origin;
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
