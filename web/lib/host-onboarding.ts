import { readApiResponse } from "@/lib/client-api";

export type HostConnection = {
  alias: string; address: string; user: string; port: string; group: string; become: boolean; credentialId: string | null;
};
export type OnboardingSecrets = { password: string; sudoPassword: string; configureSudo: boolean };
export type OnboardingStage = "trust" | "bootstrap" | "preflight" | "save";
type ApiPayload = Awaited<ReturnType<typeof readApiResponse>>;

/**
 * A password-based sudo session cannot be reused by scheduled audits.  On the
 * first non-root connection, use the supplied password once to establish the
 * HCP-managed non-interactive path; neither input is persisted.
 */
export function onboardingSecretsForUser(user: string, password: string, alternateSudoPassword = ""): OnboardingSecrets {
  const configureSudo = Boolean(password) && user.trim() !== "root";
  return { password, sudoPassword: configureSudo ? (alternateSudoPassword || password) : "", configureSudo };
}

export function defaultHostAlias(address: string) {
  return address.trim() ? `host-${address.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "-")}`.slice(0, 64) : "";
}

// A single UI action. Do not save until authentication and preflight succeed.
// Only the bootstrap request may receive the one-time passwords.
export async function connectAndSaveHost(connection: HostConnection, secrets: OnboardingSecrets, options: {
  editing: boolean; request?: typeof fetch;
  onStage?: (stage: OnboardingStage) => void;
  onPasswordSubmit?: () => void;
  onCredential?: (payload: ApiPayload) => void;
  onPreflight?: (payload: ApiPayload, credentialId: string | null) => void;
}) {
  const request = options.request ?? fetch;
  const { alias, address, user, port, group, become } = connection;
  let credentialId = connection.credentialId;
  // A retained individual key means only that SSH is ready.  It does not mean
  // that the one-time sudo setup completed.  In particular, after a failed
  // first attempt the form has a credentialId but must not silently fall
  // through to an Ansible `sudo -n` preflight without the administrator
  // password that is needed to repair the setup.
  if (!options.editing && become && user.trim() !== "root" && !secrets.password) {
    options.onStage?.("bootstrap");
    return {
      ok: false,
      stage: "bootstrap" as const,
      payload: {
        ok: false,
        error: "sudo_password_required",
        message: "Ключ SSH уже сохранён, но для первого добавления HCP должен завершить настройку прав администратора. Введите пароль пользователя Astra и повторите подключение; новая ключевая пара не создаётся.",
      } as ApiPayload,
    };
  }
  const send = async (url: string, body: object, method = "POST") => readApiResponse(await request(url, {
    method, credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  }));
  try {
    options.onStage?.("trust");
    const trust = await send("/api/ansible/access", { operation: "status", address, port });
    if (!trust.ok || !trust.trusted) return { ok: false, stage: "trust" as const, payload: trust };
    if (secrets.password || secrets.configureSudo || (!credentialId && !options.editing)) {
      options.onStage?.("bootstrap");
      options.onPasswordSubmit?.();
      const credential = await send("/api/ansible/hosts/bootstrap", {
        alias, address, user, port, credentialId, password: secrets.password, sudoPassword: secrets.sudoPassword,
        configureSudo: secrets.configureSudo, confirmRootAccess: secrets.configureSudo,
      });
      secrets.password = ""; secrets.sudoPassword = "";
      // The individual key may already be verified even when the next step
      // (for example, automatic sudo preparation) is rejected.  Keep that
      // exact credential in the form so a retry repairs the same connection
      // rather than creating another key pair.
      if (!credential.ok) {
        if (typeof credential.credentialId === "string" && credential.credentialId) options.onCredential?.(credential);
        return { ok: false, stage: "bootstrap" as const, payload: credential };
      }
      credentialId = credential.credentialId;
      options.onCredential?.(credential);
    }
    options.onStage?.("preflight");
    const preflight = await send("/api/ansible/hosts/preflight", { alias, address, user, port, become, credentialId });
    options.onPreflight?.(preflight, credentialId);
    if (!preflight.ok) return { ok: false, stage: "preflight" as const, payload: preflight };
    options.onStage?.("save");
    const saved = await send("/api/ansible/hosts", { alias, address, user, port, group, become, credentialId }, options.editing ? "PUT" : "POST");
    return { ok: Boolean(saved.ok), stage: "save" as const, payload: saved };
  } finally {
    secrets.password = ""; secrets.sudoPassword = "";
  }
}
