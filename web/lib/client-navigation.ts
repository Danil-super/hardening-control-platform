/** Only allow local page destinations, including when the browser normalizes URLs. */
export function normalizeNextPath(value: string | undefined) {
  if (!value || !value.startsWith("/") || value.startsWith("//") || /[\\\u0000-\u0020]/.test(value)) return "/hosts";
  try {
    const url = new URL(value, "https://hcp.invalid");
    const pathname = decodeURIComponent(url.pathname);
    if (url.origin !== "https://hcp.invalid" || /[\\\u0000-\u0020]/.test(pathname)
      || pathname.startsWith("//") || /^\/(login|api)(\/|$)/.test(pathname)) return "/hosts";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch { return "/hosts"; }
}

export async function signIn(password: string, nextPath: string, dependencies: {
  request: typeof fetch;
  navigate: (path: string) => void;
}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await dependencies.request("/api/ansible/auth/login", {
      method: "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal,
      headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password }),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || payload?.ok !== true) {
      throw new Error(payload?.message || "Не удалось выполнить вход. Повторите попытку.");
    }
    const session = await dependencies.request("/api/ansible/session", {
      credentials: "same-origin", cache: "no-store", signal: controller.signal,
    });
    if (session.status === 401) {
      throw new Error("Пароль принят, но сеанс не сохранился. Разрешите cookies для этого сайта и повторите вход.");
    }
    if (!session.ok || (await session.json().catch(() => null))?.ok !== true) {
      throw new Error("Не удалось подтвердить сеанс. Повторите вход.");
    }
    // A document navigation reads the new HttpOnly cookie and cannot reuse a
    // prefetched redirect to /login from Next's client router cache.
    dependencies.navigate(normalizeNextPath(nextPath));
  } catch (error) {
    if (controller.signal.aborted) throw new Error("Сервер не ответил вовремя. Повторите вход.");
    if (error instanceof TypeError) throw new Error("Нет связи с платформой. Проверьте подключение и повторите вход.");
    throw error;
  } finally { clearTimeout(timer); }
}
