export type SecurityEvent = { source?: string; message?: string };
export type ReadableSecurityEvent = {
  title: string;
  time: string | null;
  fields: Array<{ label: string; value: string }>;
  raw: string;
};

const sources: Record<string, { title: string; description: string }> = {
  ufw_denied: { title: "Соединения, заблокированные межсетевым экраном", description: "UFW отклонил сетевые пакеты. Такие записи могут появляться при проверке портов; сами по себе они не подтверждают атаку или взлом." },
  auth_failed: { title: "Неудачные попытки входа", description: "Служба входа отклонила авторизацию. Проверьте адрес отправителя и учётную запись: причиной может быть неверный пароль или автоматический подбор." },
  suricata_fast: { title: "Срабатывания Suricata", description: "Система обнаружения вторжений зарегистрировала совпадение с правилом. Значимость срабатывания требует проверки." },
  suricata_eve: { title: "События Suricata", description: "Сетевой датчик зарегистрировал предупреждение или блокировку. Срабатывание правила ещё не подтверждает успешное проникновение." },
  kernel_network: { title: "Сетевые сообщения ядра", description: "Ядро зарегистрировало отклонённый или необычный сетевой трафик. Подробности доступны в исходной записи." },
};

export function describeSecurityEvent(event: SecurityEvent): ReadableSecurityEvent {
  const raw = typeof event?.message === "string" ? event.message : "";
  const source = typeof event?.source === "string" ? event.source : "unknown";
  const fields: ReadableSecurityEvent["fields"] = [];
  const add = (label: string, value: string | undefined) => { if (value) fields.push({ label, value }); };
  // Keep journal time as written: syslog does not include the year or timezone.
  let time = raw.match(/(?:^|:)([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s/)?.[1]
    ?? raw.match(/^(\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)/)?.[1] ?? null;
  let title = "Запись журнала";
  if (source === "ufw_denied" && /\[UFW (?:BLOCK|DENY)\]/.test(raw)) {
    const tokens = Object.fromEntries([...raw.matchAll(/\b(IN|SRC|DST|PROTO|SPT|DPT)=([^\s]+)/g)].map((match) => [match[1], match[2]]));
    title = "Соединение заблокировано";
    add("Откуда", tokens.SRC); add("Куда", tokens.DST);
    add("Порт назначения", tokens.DPT); add("Протокол", tokens.PROTO); add("Интерфейс", tokens.IN);
  } else if (source === "auth_failed") {
    title = /invalid user/i.test(raw) ? "Вход с неизвестной учётной записью" : "Авторизация отклонена";
    add("Учётная запись", raw.match(/(?:Failed password for (?:invalid user )?|Invalid user )([^\s]+)/i)?.[1] ?? raw.match(/\buser=([^\s]+)/)?.[1]);
    add("Адрес отправителя", raw.match(/\bfrom ([^\s]+)/)?.[1] ?? raw.match(/\brhost=([^\s]+)/)?.[1]);
  } else if (source === "suricata_eve") {
    try {
      const data = JSON.parse(raw);
      if (data && typeof data === "object" && !Array.isArray(data)) {
        const value = (v: unknown) => typeof v === "string" || typeof v === "number" ? String(v) : undefined;
        title = value(data.alert?.signature) ?? "Сетевое событие Suricata";
        time = value(data.timestamp) ?? time;
        add("Откуда", value(data.src_ip)); add("Куда", value(data.dest_ip));
        add("Порт назначения", value(data.dest_port)); add("Протокол", value(data.proto));
        add("Правило", value(data.alert?.signature_id));
        const action = value(data.alert?.action);
        add("Действие датчика", action === "blocked" ? "Заблокировано" : action === "allowed" ? "Пропущено" : action);
      }
    } catch { title = "Сетевое событие Suricata — детали в журнале"; }
  } else if (source === "suricata_fast") {
    title = raw.match(/\[\*\*\]\s+\[[^\]]+\]\s+(.+?)\s+\[\*\*\]/)?.[1] ?? "Срабатывание правила Suricata";
    add("Протокол", raw.match(/\{([^}]+)\}/)?.[1]);
  }
  return { title, time, fields, raw };
}

export function groupSecurityEvents(events: SecurityEvent[]) {
  const groups = new Map<string, { source: string; title: string; description: string; events: ReadableSecurityEvent[] }>();
  for (const event of events) {
    const source = typeof event?.source === "string" ? event.source : "unknown";
    const group = groups.get(source) ?? { source, ...(sources[source] ?? { title: "Другие записи журнала", description: "Для этого источника автоматическая расшифровка недоступна. Ознакомьтесь с исходными записями." }), events: [] };
    group.events.push(describeSecurityEvent(event));
    groups.set(source, group);
  }
  return [...groups.values()];
}
