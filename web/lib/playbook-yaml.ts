import { isSeq, LineCounter, parseDocument } from "yaml";

const errorMessages: Record<string, string> = {
  BAD_INDENT: "Проверьте отступы.",
  TAB_AS_INDENT: "Используйте пробелы вместо табуляции в отступах.",
  DUPLICATE_KEY: "Ключ повторяется в одном блоке.",
  MISSING_CHAR: "Проверьте незакрытые скобки или кавычки.",
  MULTIPLE_DOCS: "Сценарий должен содержать один YAML-документ.",
};

export function playbookYamlIssue(content: string): { message: string; line?: number; col?: number } | null {
  if (content.length > 512 * 1024) return { message: "Для большого сценария проверьте YAML в тестовом контуре." };

  const lines = new LineCounter();
  try {
    // Inspect source structure only. Ansible tags and aliases are never resolved to values.
    const document = parseDocument(content, { version: "1.1", lineCounter: lines, prettyErrors: false });
    const issue = document.errors[0];
    if (issue) {
      const offset = issue.pos[0] === content.length ? content.trimEnd().length : issue.pos[0];
      return { ...lines.linePos(offset), message: errorMessages[issue.code] ?? issue.message };
    }
    if (!isSeq(document.contents) || document.contents.items.length === 0) {
      return { ...lines.linePos(document.contents?.range?.[0] ?? 0), message: "Ожидается список блоков Ansible, каждый начинается с дефиса." };
    }
    return null;
  } catch {
    return { message: "Не удалось разобрать YAML. Упростите вложенность и проверьте отступы." };
  }
}
