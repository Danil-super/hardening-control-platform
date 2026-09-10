import { timingSafeEqual } from "node:crypto";

export function isScheduledRequestAuthorized(request: Request) {
  const expected = Buffer.from(process.env.HCP_SCHEDULE_API_KEY?.trim() ?? "");
  const received = Buffer.from(request.headers.get("x-hcp-schedule-key")?.trim() ?? "");
  return expected.length > 0 && expected.length === received.length && timingSafeEqual(expected, received);
}

export function isScheduledRunId(value: unknown): value is string {
  return typeof value === "string" && /^schedule-[A-Za-z0-9_.:-]{8,120}$/.test(value);
}
