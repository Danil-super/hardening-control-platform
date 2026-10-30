/** POSIX shell only: non-systemd hosts may keep their persistent ID in D-Bus.
 * Never generate an identity during a read-only probe. An existing invalid or
 * unreadable primary file must fail rather than silently select another ID.
 */
export function machineIdentityProbeCommand(paths: readonly [string, string] = ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
  const quote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;
  if (paths.some((value) => !value.startsWith("/") || /[\0\r\n]/.test(value))) throw new Error("Недопустимый путь идентификатора машины.");
  return `LC_ALL=C; export LC_ALL; hcp_identity_path=${quote(paths[0])}; `
    + `if [ ! -e "$hcp_identity_path" ] && [ ! -L "$hcp_identity_path" ]; then hcp_identity_path=${quote(paths[1])}; fi; `
    + "hcp_machine_id=; if IFS= read -r hcp_machine_id < \"$hcp_identity_path\" || [ -n \"$hcp_machine_id\" ]; then "
    + "printf 'HCP_MACHINE_ID=%s\\n' \"$hcp_machine_id\"; else exit 1; fi";
}
