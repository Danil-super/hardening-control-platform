/**
 * Ansible's JSON extra-vars decoder recognizes this unsafe-string marker and
 * carries it through recursive templating/from_json. Ordinary JSON escaping
 * only protects argv parsing: it does not stop Jinja lookups in a string.
 * Keep caller-controlled configuration, paths and passwords literal, including
 * legitimate values which happen to contain {{, {% or {#.
 */
export function ansibleLiteralExtraVars(values: Record<string, string | boolean>) {
  const literal: Record<string, { __ansible_unsafe: string } | boolean> = Object.create(null);
  for (const [key, value] of Object.entries(values)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || (typeof value !== "string" && typeof value !== "boolean")) {
      throw new Error("Переменные Ansible должны иметь допустимые имена и строковые либо логические значения.");
    }
    // Internal recovery attestations must retain their boolean type. Strings
    // still use Ansible's unsafe marker; nested structures remain forbidden.
    literal[key] = typeof value === "boolean" ? value : { __ansible_unsafe: value };
  }
  return JSON.stringify(literal);
}
