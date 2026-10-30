/** Only explicit interpreter paths can be carried into the trusted SSH probe. */
export function targetPythonInterpreter(value: unknown = "/usr/bin/python3") {
  if (typeof value !== "string" || !/^(?:\/[A-Za-z0-9_.+-]+)+$/.test(value)) {
    throw Object.assign(new Error("Укажите явный абсолютный путь ansible_python_interpreter."), { code: "target_python_path_invalid" });
  }
  return value;
}

export function targetPythonProbeCommand(interpreter: string) {
  const executable = targetPythonInterpreter(interpreter);
  return `'${executable}' -c 'import sys; print("HCP_PYTHON=%s.%s.%s" % sys.version_info[:3])'`;
}

/** Missing, malformed and conflicting observations must not select a runtime. */
export function parseTargetPythonVersion(stdout: string) {
  const lines = stdout.split(/\r?\n/).filter((line) => line.startsWith("HCP_PYTHON="));
  if (lines.length !== 1) return null;
  return lines[0].match(/^HCP_PYTHON=(\d{1,2}\.\d{1,2}\.\d{1,3})$/)?.[1] ?? null;
}
