export type AstraOvalConfig = {
  mode: "local" | "online";
  path: string;
  url: string;
  sha256: string;
  releasePattern: string;
  architectures: string[];
  maxAgeDays: number;
};

export function validateAstraOvalConfig(value: unknown): AstraOvalConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Укажите настройки OVAL-базы.");
  const input = value as Record<string, unknown>;
  const text = (key: string) => typeof input[key] === "string" ? input[key].trim() : "";
  if (input.mode !== "local" && input.mode !== "online") throw new Error("Выберите локальную или сетевую OVAL-базу.");
  const file = text("path");
  const url = text("url");
  const sha256 = text("sha256").toLowerCase();
  const releasePattern = text("releasePattern");
  if (input.mode === "local" && (!file.startsWith("/") || file.length > 1024 || /[\x00-\x1f\x7f]/.test(file) || file.split("/").includes(".."))) {
    throw new Error("Укажите абсолютный путь к XML-базе на проверяемом хосте без переходов ..");
  }
  if (input.mode === "online") {
    let parsed: URL;
    try { parsed = new URL(url); } catch { throw new Error("Укажите полный HTTPS-адрес XML-базы."); }
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.hash || parsed.search || url.length > 2048) {
      throw new Error("Нужен HTTPS-адрес без пароля, параметров запроса и фрагмента. Для закрытой сети используйте внутреннее HTTPS-зеркало.");
    }
    if (!sha256) throw new Error("Для сетевой базы укажите ожидаемый SHA-256 из доверенного источника.");
  }
  if (sha256 && !/^[a-f0-9]{64}$/.test(sha256)) throw new Error("SHA-256 должен содержать 64 шестнадцатеричных символа.");
  if (!/^(?:\*|[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}(?:\.\*)?)$/.test(releasePattern)) {
    throw new Error("Укажите точный выпуск, ветку с .* на конце или * для базы с собственными условиями применимости.");
  }
  if (!Array.isArray(input.architectures) || input.architectures.length > 16 || !input.architectures.every((item) => typeof item === "string" && /^[A-Za-z0-9_-]{1,32}$/.test(item))) {
    throw new Error("Архитектуры задаются списком значений uname -m; пустой список не вводит дополнительного ограничения.");
  }
  const maxAgeDays = input.maxAgeDays;
  if (typeof maxAgeDays !== "number" || !Number.isInteger(maxAgeDays) || maxAgeDays < 1 || maxAgeDays > 3650) {
    throw new Error("Допустимый возраст базы — целое число от 1 до 3650 дней.");
  }
  return { mode: input.mode, path: input.mode === "local" ? file : "", url: input.mode === "online" ? url : "", sha256,
    releasePattern, architectures: [...new Set(input.architectures as string[])], maxAgeDays };
}
