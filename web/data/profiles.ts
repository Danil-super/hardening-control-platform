import type { AuditProfile } from "@/types";

export const auditProfiles: AuditProfile[] = [
  {
    id: "basic_linux",
    title: "Базовое усиление Linux",
    description:
      "Базовый аудит Linux-сервера: обновления, межсетевой экран, открытые порты, пользователи и защита входа.",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    categories: ["Межсетевой экран", "Сеть", "Аутентификация", "Обновления", "Файловая система"],
    rulesCount: 8,
    severityFocus: ["high", "medium", "low"],
  },
  {
    id: "ssh_security",
    title: "Безопасность SSH",
    description:
      "Проверка безопасности SSH: вход root, парольная авторизация, ключи и ограничения попыток входа.",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    categories: ["SSH", "Аутентификация"],
    rulesCount: 5,
    severityFocus: ["high", "medium"],
  },
  {
    id: "web_server",
    title: "Усиление веб-сервера",
    description:
      "Проверки Nginx/Apache: защитные заголовки, раскрытие версии сервера, HTTPS и листинг директорий.",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    categories: ["Веб"],
    rulesCount: 5,
    severityFocus: ["high", "medium", "low"],
  },
  {
    id: "docker_host",
    title: "Усиление Docker-хоста",
    description:
      "Проверки Docker-хоста: привилегированные контейнеры, docker.sock, root-пользователь и открытые порты.",
    supportedOs: ["Ubuntu 22.04+", "Ubuntu 24.04", "Debian 12"],
    categories: ["Docker", "Сеть"],
    rulesCount: 4,
    severityFocus: ["high", "medium"],
  },
];

export function getProfile(profileId: string) {
  return auditProfiles.find((profile) => profile.id === profileId);
}
