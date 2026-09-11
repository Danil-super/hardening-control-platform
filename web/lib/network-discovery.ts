export const maxHostsPerScan = 254;

export function ipToInt(ip: string) {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function intToIp(value: number) {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join(".");
}

export function isPrivateIp(ip: string) {
  const parts = ip.split(".").map((part) => Number(part));
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254)
  );
}

export function parseCidr(cidr: string) {
  const match = cidr.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match) {
    return null;
  }
  const base = ipToInt(match[1]);
  const prefix = Number(match[2]);
  if (base === null || !Number.isInteger(prefix) || prefix < 24 || prefix > 30 || !isPrivateIp(match[1])) {
    return null;
  }

  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const count = Math.max(0, broadcast - network - 1);
  if (count > maxHostsPerScan) {
    return null;
  }
  return { base: match[1], prefix, network, broadcast, count };
}

export function listHosts(cidr: string) {
  const parsed = parseCidr(cidr);
  if (!parsed) {
    return [];
  }
  const hosts: string[] = [];
  for (let value = parsed.network + 1; value < parsed.broadcast; value += 1) {
    hosts.push(intToIp(value));
  }
  return hosts;
}

export function ipInCidr(ip: string, cidr: string) {
  const parsed = parseCidr(cidr);
  const value = ipToInt(ip);
  return Boolean(parsed && value !== null && value > parsed.network && value < parsed.broadcast);
}

export type NetworkCandidate = {
  cidr: string;
  device?: string;
  origin: "target" | "site" | "interface" | "container";
  label: string;
};

/** Suggestions only; neither discovery nor trust is triggered by this helper. */
export function buildNetworkSuggestions(input: {
  routes: string; inContainer: boolean; targetAddress: string; siteHostname: string;
  interfaces: Array<{ device: string; address: string; cidr: string | null }>;
}) {
  const candidates: NetworkCandidate[] = [];
  const add = (cidr: string, origin: NetworkCandidate["origin"], label: string, device?: string) => {
    const parsed = parseCidr(cidr);
    if (!parsed) return;
    const normalized = `${intToIp(parsed.network)}/${parsed.prefix}`;
    if (!candidates.some((candidate) => candidate.cidr === normalized)) candidates.push({ cidr: normalized, origin, label, device });
  };
  for (const [address, origin, label] of [
    [input.targetAddress, "target", "По адресу хоста; проверьте диапазон /24"],
    [input.siteHostname, "site", "По адресу сайта; проверьте сеть Astra и диапазон /24"],
  ] as const) {
    if (ipToInt(address) !== null && isPrivateIp(address)) add(`${address}/24`, origin, label);
  }
  const networks = input.routes.split("\n").flatMap((line) => {
    const cidr = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})\s/)?.[1];
    const device = line.match(/\bdev\s+(\S+)/)?.[1];
    const address = line.match(/\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})/)?.[1];
    return cidr && device && address ? [{ cidr, device, address }] : [];
  });
  for (const { cidr, device, address } of [...networks, ...input.interfaces]) {
    if (!cidr || ipToInt(address) === null || !isPrivateIp(address)) continue;
    const prefix = Number(cidr.split("/")[1]);
    const container = input.inContainer || /^(docker|br-|veth|cni|flannel)/.test(device);
    add(prefix < 24 ? `${address}/24` : cidr, container ? "container" : "interface",
      container ? "Сеть контейнера; выбирайте только если цель находится в ней"
        : prefix < 24 ? "Часть сети интерфейса: диапазон ограничен /24" : "Сеть интерфейса", device);
  }
  const preferred = candidates.find((candidate) => candidate.origin !== "container");
  return {
    ok: true, candidates, defaultCidr: preferred?.cidr ?? "", maxHostsPerScan,
    message: preferred
      ? `Подставлен диапазон ${preferred.cidr}. ${preferred.label}. Проверьте его перед сканированием.`
      : input.inContainer
        ? "HCP видит сеть Docker. Укажите подсеть целевой Astra вручную, например 192.168.1.0/24."
        : "Подсеть не определена автоматически. Укажите подсеть целевого хоста вручную.",
  };
}
