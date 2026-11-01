/** Distribution identity and adapter routing, never a security verdict.
 * ID_LIKE selects collection conventions only. Advisory ownership always
 * comes from the exact distribution ID; a derivative never inherits a feed.
 */
export const LINUX_PLATFORM_REGISTRY_VERSION = 1;
export type LinuxPackageManager = "dpkg" | "rpm" | "apk";
export type PackageCveProvider = "trivy" | "astra-oval" | "vendor-required" | "none";
export type LinuxPlatform = {
  id: string;
  versionId: string;
  family: string;
  packageManager: LinuxPackageManager | null;
  trivyFamily: string | null;
  packageCveProvider: PackageCveProvider;
  collectionFamilyInferred: boolean;
  notes: string[];
};

type Adapter = { family: string; manager: LinuxPackageManager | null; trivy?: string; provider?: PackageCveProvider };
const adapters: Record<string, Adapter> = {
  debian: { family: "debian", manager: "dpkg", trivy: "debian" },
  ubuntu: { family: "debian", manager: "dpkg", trivy: "ubuntu" },
  astra: { family: "astra", manager: "dpkg", provider: "astra-oval" },
  astralinux: { family: "astra", manager: "dpkg", provider: "astra-oval" },
  rhel: { family: "rhel", manager: "rpm", trivy: "redhat" },
  redhat: { family: "rhel", manager: "rpm", trivy: "redhat" },
  redhatenterpriseserver: { family: "rhel", manager: "rpm", trivy: "redhat" },
  rocky: { family: "rhel", manager: "rpm", trivy: "rocky" },
  almalinux: { family: "rhel", manager: "rpm", trivy: "alma" },
  alma: { family: "rhel", manager: "rpm", trivy: "alma" },
  centos: { family: "rhel", manager: "rpm", trivy: "centos" },
  ol: { family: "rhel", manager: "rpm", trivy: "oracle" },
  amzn: { family: "rhel", manager: "rpm", trivy: "amazon" },
  fedora: { family: "rhel", manager: "rpm", provider: "vendor-required" },
  "centos-stream": { family: "rhel", manager: "rpm", provider: "vendor-required" },
  // These are Trivy v0.74.0 pkg/fanal/types constants, not display names.
  sles: { family: "suse", manager: "rpm", trivy: "sles" },
  sled: { family: "suse", manager: "rpm", provider: "vendor-required" },
  "opensuse-leap": { family: "suse", manager: "rpm", trivy: "opensuse-leap" },
  "opensuse-tumbleweed": { family: "suse", manager: "rpm", trivy: "opensuse-tumbleweed" },
  opensuse: { family: "suse", manager: "rpm", provider: "vendor-required" },
  slem: { family: "suse", manager: "rpm", provider: "vendor-required" },
  photon: { family: "photon", manager: "rpm", provider: "vendor-required" },
  "cbl-mariner": { family: "azurelinux", manager: "rpm", provider: "vendor-required" },
  azurelinux: { family: "azurelinux", manager: "rpm", provider: "vendor-required" },
  alpine: { family: "alpine", manager: "apk", trivy: "alpine" },
  wolfi: { family: "alpine", manager: "apk", trivy: "wolfi" },
  chainguard: { family: "alpine", manager: "apk", provider: "vendor-required" },
  altlinux: { family: "alt", manager: "rpm", provider: "vendor-required" },
  alt: { family: "alt", manager: "rpm", provider: "vendor-required" },
  redos: { family: "redos", manager: "rpm", provider: "vendor-required" },
  rosa: { family: "rosa", manager: "rpm", provider: "vendor-required" },
  arch: { family: "arch", manager: null, provider: "vendor-required" },
  gentoo: { family: "gentoo", manager: null, provider: "vendor-required" },
  nixos: { family: "nixos", manager: null, provider: "vendor-required" },
};

function identity(value: unknown) {
  return typeof value === "string" && /^[a-zA-Z0-9._-]{1,80}$/.test(value.trim()) ? value.trim().toLowerCase() : "";
}

export function resolveLinuxPlatform(osRelease: Record<string, string>, astraVersion?: string | null): LinuxPlatform {
  const id = identity(osRelease.ID);
  const versionId = typeof osRelease.VERSION_ID === "string" && osRelease.VERSION_ID.length <= 160 ? osRelease.VERSION_ID.trim() : "";
  const notes: string[] = [];
  const astraEvidence = Boolean(astraVersion) || id.startsWith("astra") || /astra/i.test(osRelease.NAME ?? "");
  let adapter = astraEvidence ? adapters.astra : adapters[id];
  let collectionFamilyInferred = false;
  if (!adapter) {
    const relatives = typeof osRelease.ID_LIKE === "string" ? osRelease.ID_LIKE.split(/\s+/).map(identity) : [];
    const parent = relatives.map((relative) => adapters[relative]).find((candidate) => candidate?.manager);
    if (parent) {
      adapter = { family: parent.family, manager: parent.manager, provider: "vendor-required" };
      collectionFamilyInferred = true;
      notes.push("ID_LIKE использован только для выбора способа сбора; CVE-база родительского дистрибутива не наследуется.");
    }
  }
  if (!id) notes.push("Точный идентификатор дистрибутива не получен; применимость источников CVE не подтверждена.");
  if (!versionId) notes.push("Версия ОС не получена; применимость базы и профиля требует отдельной проверки.");
  let provider = adapter?.provider ?? (adapter?.trivy ? "trivy" : "vendor-required");
  // CentOS Stream is a separate advisory population, despite ID=centos.
  const stream = id === "centos" && /stream/i.test([osRelease.NAME, osRelease.PRETTY_NAME, osRelease.VARIANT, osRelease.VARIANT_ID].filter(Boolean).join(" "));
  if (stream) {
    provider = "vendor-required";
    notes.push("CentOS Stream не получает подтверждение CVE-покрытия из базы обычного CentOS.");
  }
  if (provider === "vendor-required") notes.push("Для точного дистрибутива нужен подтверждённый источник производителя; общий аудит и инвентаризация доступны независимо от него.");
  if (provider === "trivy") notes.push("Trivy должен подтвердить точный выпуск, обработанные пакеты и пригодность базы во время аудита; наличие адаптера не означает полное CVE-покрытие.");
  if (provider === "astra-oval") notes.push("Для CVE Astra требуется OVAL-источник её выпуска и архитектуры; база Debian не заменяет его.");
  return { id: id || "unknown", versionId, family: adapter?.family ?? "other", packageManager: adapter?.manager ?? null,
    trivyFamily: provider === "trivy" ? adapter?.trivy ?? null : null, packageCveProvider: provider,
    collectionFamilyInferred, notes };
}
