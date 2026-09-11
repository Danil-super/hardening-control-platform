export async function copyText(value: string) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
  } catch { /* HTTP LAN deployments and denied clipboard permission need a fallback. */ }
  const active = document.activeElement as HTMLElement | null;
  const field = document.createElement("textarea");
  field.value = value;
  field.readOnly = true;
  field.style.cssText = "position:fixed;top:0;left:0;opacity:0;pointer-events:none";
  document.body.appendChild(field);
  try {
    field.select();
    if (!document.execCommand("copy")) throw new Error("copy_failed");
  } finally {
    field.remove();
    active?.focus({ preventScroll: true });
  }
}
