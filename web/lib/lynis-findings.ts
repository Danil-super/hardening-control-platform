import { createHash } from "node:crypto";
import controls from "@/lib/lynis-controls.json";
import type { Finding } from "@/types";

type Control = { title: string; category: string; recommendation: string; impact: string; messagePattern: string; observation: string; reference: string };
const catalog: Record<string, Control> = controls.controls;
const field = (value: unknown) => typeof value === "string" && value !== "-" ? value : "";

function observation(rule: string, message: string, details: string, control?: Control) {
  let title = control?.title ?? `Проверка Lynis ${rule}`;
  let description = message || "Lynis не сохранил текст наблюдения; содержание проверки нужно уточнить по её коду.";
  let recommendation = control?.recommendation ?? "Просмотрите оригинальное сообщение и описание проверки Lynis. Конкретные действия для неизвестного правила HCP не подставляет автоматически.";
  const translated = Boolean(control && new RegExp(control.messagePattern, "i").test(message));
  if (translated && control?.observation) description = control.observation;
  if (rule === "NAME-4210") {
    if (/^Found BIND version in banner/.test(message)) description = "Lynis обнаружил версию BIND в ответе на локальный DNS-запрос.";
    else if (/^The version in BIND can be masked/.test(message)) {
      title = "Проверить скрытие версии BIND";
      description = "Lynis рекомендует скрыть версию BIND с помощью параметра version none в конфигурации DNS-сервера.";
    }
  }
  if (rule === "GEN-0010") {
    const match = message.match(/^This version (\S+) is marked end-of-life as of (\d{4}-\d{2}-\d{2})/);
    if (match) description = `Lynis считает распознанный выпуск ${match[1]} неподдерживаемым с ${match[2]}. Это сообщение нужно сверить с фактическим выпуском и поддержкой Astra.`;
  }
  if (rule === "SSH-7408") {
    const match = details.match(/^([A-Za-z][A-Za-z0-9]*) \(set (.{0,64}?) to (.{0,64}?)\)$/);
    if (match) {
      title = `Проверить SSH: ${match[1]}`;
      description = `Lynis указал значение ${match[2]} для ${match[1]}. ${match[3] ? `Профиль Lynis предлагает ${match[3]}; это предложение, а не обязательная настройка для любого сервера.` : "Предложенное значение в отчёте отсутствует."}`;
      if (!match[3]) recommendation = `Для ${match[1]} предложенное значение отсутствует. Не меняйте параметр по этой пустой рекомендации. Проверьте действующую конфигурацию SSH и требования к подключению; новое значение HCP не придумывает.`;
      else {
        const roles: Record<string, string> = {
          AllowTcpForwarding: "Уточните, нужны ли SSH-туннели для администрирования или приложений.",
          AllowAgentForwarding: "Уточните, требуется ли передача SSH-агента на этот сервер: доступ к агенту может использоваться для последующей аутентификации.",
          X11Forwarding: "Уточните, требуется ли запуск графических приложений через SSH.",
          LogLevel: "Оцените детализацию журналов, место для их хранения и доступ к ним.",
          MaxAuthTries: "Проверьте ограничение попыток входа, включая клиентов, которые предлагают несколько SSH-ключей.",
          MaxSessions: "Проверьте, сколько каналов в одном соединении используют ваши приложения и средства администрирования.",
          ClientAliveCountMax: "Оцените влияние изменения на завершение неотвечающих соединений и нестабильные каналы связи.",
          TCPKeepAlive: "Проверьте требования к обнаружению разрыва соединения и сетевые таймауты.",
          Compression: "Проверьте необходимость сжатия SSH-трафика и влияние на ресурсы сервера.",
        };
        recommendation = `${roles[match[1]] ?? "Сверьте назначение параметра с документацией SSH и ролью хоста."} Предложение Lynis: ${match[1]} = ${match[3]}. Перед изменением сохраните конфигурацию, проверьте её корректность и новый вход, не закрывая текущую сессию.`;
      }
    }
  }
  if (rule === "FILE-6310") {
    const match = message.match(/^To decrease the impact of a full (\/[\w/.-]+) file system/);
    if (match) { title = `Проверить изоляцию каталога ${match[1]}`; description = `Lynis предлагает отдельную файловую систему для ${match[1]}, чтобы её заполнение меньше влияло на остальные части системы.`; }
  }
  if (rule === "NETW-3200") {
    const match = message.match(/^Determine if protocol '(dccp|sctp|rds|tipc)' is really needed/i);
    if (match) { title = `Проверить необходимость протокола ${match[1].toUpperCase()}`; description = `Lynis предлагает проверить, используется ли протокол ${match[1]} приложениями этого хоста.`; }
  }
  if (rule === "AUTH-9286") {
    const match = message.match(/^Configure (minimum|maximum) password age/);
    if (match) { const age = match[1] === "minimum" ? "минимальный" : "максимальный"; title = `Проверить ${age} срок смены пароля`; description = `Lynis рекомендует проверить ${age} срок смены пароля в /etc/login.defs. Значение, установленное на хосте, в этой записи не приведено.`; }
  }
  if (rule === "PKGS-7346") {
    const match = message.match(/\((\d+) found\)/);
    if (match) description = `Lynis нашёл удалённые пакеты с оставшимися конфигурациями: ${match[1]}. Проверьте, нужны ли эти настройки и связанные файлы.`;
  }
  return { title, description, recommendation, translated };
}

export function normalizeLynisFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, number>();
  return findings.map((finding) => {
    if (finding.source !== "lynis") return finding;
    const legacy = finding.id.match(/^lynis_(warning|suggestion)_([A-Z]+(?:-\d+)?)(?:_[a-f0-9]{12}(?:_\d+)?)?$/);
    const data = finding.lynis;
    const kind = data?.kind === "warning" || data?.kind === "suggestion" ? data.kind : legacy?.[1];
    const rule = typeof data?.ruleId === "string" && /^[A-Z]+(?:-\d+)?$/.test(data.ruleId) ? data.ruleId : legacy?.[2];
    if (!rule || kind !== "warning" && kind !== "suggestion") return finding;
    const parts = (finding.evidence ?? "").split("|");
    const message = data && typeof data.message === "string" ? data.message : field(parts[0]);
    const details = data && typeof data.details === "string" ? data.details : field(parts[1]);
    const solution = data && typeof data.solution === "string" ? data.solution : field(parts[2]);
    const rawRecord = data && typeof data.rawRecord === "string" ? data.rawRecord : `${rule}|${finding.evidence ?? ""}`;
    const digest = createHash("sha256").update(rawRecord).digest("hex").slice(0, 12);
    const baseId = `lynis_${kind}_${rule}_${digest}`;
    const occurrence = (seen.get(baseId) ?? 0) + 1; seen.set(baseId, occurrence);
    const control = catalog[rule];
    const text = observation(rule, message, details, control);
    return { ...finding, id: occurrence === 1 ? baseId : `${baseId}_${occurrence}`, title: text.title,
      description: text.description, recommendation: text.recommendation, category: control?.category ?? "Другие проверки Lynis",
      risk: "info", severityUnknown: true, severityAssessment: undefined, status: "manual", remediationAvailable: false,
      lynis: { ruleId: rule, kind, message, details, solution, rawRecord, reference: control?.reference ?? `https://cisofy.com/lynis/controls/${rule}/`,
        impact: control?.impact ?? "Для этого правила в HCP пока нет проверенного пояснения последствий. Оригинальное сообщение сохранено; уровень риска не назначен.",
        explanationKnown: Boolean(control), messageTranslated: text.translated },
    };
  });
}
