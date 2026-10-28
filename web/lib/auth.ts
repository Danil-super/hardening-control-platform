import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { deleteAdminSession, hasActiveAdminSession, storeAdminSession } from "@/lib/state-store";

export const authCookieName = "hcp_admin_session";
export const sessionMaxAgeSeconds = 60 * 60 * 8;

export function getAdminPassword() {
  return process.env.HCP_ADMIN_PASSWORD?.trim() || "";
}

export function getAuthSecret() {
  return process.env.HCP_AUTH_SECRET?.trim() || getAdminPassword();
}

export function isAuthConfigured() {
  return Boolean(getAdminPassword());
}

function credentialGeneration() {
  const password = getAdminPassword();
  const secret = getAuthSecret();
  return password && secret
    ? createHmac("sha256", secret).update("hcp-admin-session-v1\0").update(password).digest("hex")
    : "";
}

function sessionHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export function createSessionToken() {
  const generation = credentialGeneration();
  if (!generation) return "";
  const token = randomBytes(32).toString("hex");
  const now = Date.now();
  storeAdminSession(sessionHash(token), generation, now, now + sessionMaxAgeSeconds * 1000);
  return token;
}

export function isValidSessionToken(token: unknown) {
  const generation = credentialGeneration();
  if (!generation || typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)) return false;
  return hasActiveAdminSession(sessionHash(token), generation, Date.now());
}

export function revokeSessionToken(token: unknown) {
  if (typeof token === "string" && /^[a-f0-9]{64}$/.test(token)) deleteAdminSession(sessionHash(token));
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
