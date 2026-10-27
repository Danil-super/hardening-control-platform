/** Technical identifiers are data, not English sentences to translate. */
export function needsRussianTranslation(text: string) {
  const prose = text.split("\n").filter((line) => !/^(?:[^\s|]+\|)?cpe:(?:\/|2\.3:)\S+$/i.test(line.trim())).join("\n");
  const latin = prose.match(/[A-Za-z]/g)?.length ?? 0;
  const cyrillic = prose.match(/[А-Яа-яЁё]/g)?.length ?? 0;
  return latin > 3 && cyrillic < latin / 3;
}
