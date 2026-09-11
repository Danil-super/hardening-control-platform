// A shared decoder keeps expired sessions and non-JSON proxy errors visible.
// Preserve structured error payloads (notably individual preflight checks).
export async function readApiResponse(response: Response) {
  if (response.status === 401) throw new Error("Сеанс завершён. Войдите в платформу снова.");
  const payload = await response.json().catch(() => null);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error(`Платформа вернула некорректный ответ (HTTP ${response.status}). Повторите запрос.`);
  }
  if (!response.ok) payload.ok = false;
  return payload;
}

export function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error && !(error instanceof TypeError) ? error.message : fallback;
}
