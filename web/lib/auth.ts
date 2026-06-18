import { createHash, timingSafeEqual } from "node:crypto";

export const authCookieName = "hcp_admin_session";

export function getAdminPassword() {
  return process.env.HCP_ADMIN_PASSWORD?.trim() || "";
}

export function getAuthSecret() {
  return process.env.HCP_AUTH_SECRET?.trim() || getAdminPassword();
}

export function isAuthConfigured() {
  return Boolean(getAdminPassword());
}

export function createSessionToken() {
  const password = getAdminPassword();
  const secret = getAuthSecret();
  if (!password || !secret) {
    return "";
  }

  return createHash("sha256").update(`${password}:${secret}`).digest("hex");
}

export function isValidPassword(value: unknown) {
  const password = getAdminPassword();
  if (typeof value !== "string" || !password) {
    return false;
  }

  const left = Buffer.from(value);
  const right = Buffer.from(password);
  return left.length === right.length && timingSafeEqual(left, right);
}
