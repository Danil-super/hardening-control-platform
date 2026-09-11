import { readApiResponse } from "@/lib/client-api";

export type HostConnection = {
  alias: string; address: string; user: string; port: string; group: string; become: boolean; credentialId: string | null;
};
export type OnboardingSecrets = { password: string; sudoPassword: string; configureSudo: boolean };
export type OnboardingStage = "trust" | "bootstrap" | "preflight" | "save";
type ApiPayload = Awaited<ReturnType<typeof readApiResponse>>;

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
      if (!credential.ok) return { ok: false, stage: "bootstrap" as const, payload: credential };
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
