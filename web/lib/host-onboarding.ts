import { readApiResponse } from "@/lib/client-api";

export type HostConnection = {
  alias: string; address: string; user: string; port: string; group: string; become: boolean; credentialId: string | null;
};
export type OnboardingSecrets = { password: string; sudoPassword: string; configureSudo: boolean };
export type OnboardingStage = "trust" | "bootstrap" | "preflight" | "save";
type ApiPayload = Awaited<ReturnType<typeof readApiResponse>>;

/**
 * A password-based sudo session cannot be reused by scheduled audits.  For a
 * non-root Astra account HCP verifies it once during enrollment, then keeps
 * only the individual SSH key.  The sudo password itself is never persisted.
 */
export function onboardingSecretsForUser(user: string, password: string, alternateSudoPassword = ""): OnboardingSecrets {
  // After an interrupted first attempt the individual SSH key can already be
  // valid.  In that state an Astra policy such as `rootpw` may require only
  // the separate sudo password on retry; do not force the user to re-send an
  // otherwise unnecessary SSH password.
  const configureSudo = Boolean(password || alternateSudoPassword) && user.trim() !== "root";
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
  // that one-time sudo verification completed.  In particular, after a
  // failed first attempt the form has a credentialId but must not silently
  // fall through to a privileged preflight without the administrator
  // password that is needed to verify the connection.
  if (!options.editing && !credentialId && !secrets.password) {
    options.onStage?.("bootstrap");
    return {
      ok: false,
      stage: "bootstrap" as const,
      payload: {
        ok: false,
        error: "password_required",
        message: "Для первого подключения без сохранённого ключа введите пароль для входа по SSH.",
      } as ApiPayload,
    };
  }
  if (!options.editing && become && user.trim() !== "root" && !secrets.password && !secrets.sudoPassword) {
    options.onStage?.("bootstrap");
    return {
      ok: false,
      stage: "bootstrap" as const,
      payload: {
        ok: false,
        error: "sudo_password_required",
        message: "Ключ SSH уже сохранён, но HCP должен проверить права администратора. Введите пароль SSH или, если sudo запрашивает другой пароль, укажите его в дополнительном поле; новая ключевая пара не создаётся.",
      } as ApiPayload,
    };
  }
  const send = async (url: string, body: object, method = "POST") => readApiResponse(await request(url, {
    method, credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  }));
  // Keep this only in the current function frame long enough for the first
  // Ansible preflight.  The browser fields are cleared before the bootstrap
  // request, and no later save request receives a password.
  let onDemandSudoPassword = secrets.sudoPassword || secrets.password;
  let onDemandSudo = false;
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
      onDemandSudo = credential.sudoMode === "on_demand" || credential.sudo?.mode === "on_demand";
      options.onCredential?.(credential);
    }
    options.onStage?.("preflight");
    const preflight = await send("/api/ansible/hosts/preflight", {
      alias, address, user, port, become, credentialId,
      ...(onDemandSudo ? { sudoPassword: onDemandSudoPassword } : {}),
    });
    onDemandSudoPassword = "";
    options.onPreflight?.(preflight, credentialId);
    if (!preflight.ok) return { ok: false, stage: "preflight" as const, payload: preflight };
    options.onStage?.("save");
    const saved = await send("/api/ansible/hosts", { alias, address, user, port, group, become, credentialId }, options.editing ? "PUT" : "POST");
    return { ok: Boolean(saved.ok), stage: "save" as const, payload: saved };
  } finally {
    secrets.password = ""; secrets.sudoPassword = ""; onDemandSudoPassword = "";
  }
}
