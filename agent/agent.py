"""Audit-only Linux Agent for Hardening Control Platform.

The first agent version is intentionally read-only. It collects local signals and
returns JSON that the web platform can consume later. Remediation and rollback
commands are explicit no-op placeholders.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Risk = Literal["high", "medium", "low", "info"]
Status = Literal["failed", "passed", "fixed", "manual"]

LYNIS_PREFIX_CATEGORIES = {
    "acct": "Учетные записи",
    "auth": "Аутентификация",
    "boot": "Загрузка",
    "cron": "Планировщик задач",
    "dbs": "Базы данных",
    "dns": "DNS",
    "file": "Файловая система",
    "fire": "Межсетевой экран",
    "fs": "Файловая система",
    "hrdn": "Усиление системы",
    "krnl": "Ядро",
    "logg": "Журналирование",
    "mail": "Почта",
    "netw": "Сеть",
    "pkg": "Пакеты",
    "schd": "Планировщик задач",
    "ssh": "SSH",
    "stor": "Хранилище",
    "strg": "Хранилище",
    "tool": "Инструменты безопасности",
}

LYNIS_TEST_MAPPINGS = {
    "schd-7704": {
        "category": "Планировщик задач",
        "remediation_id": "review_cron_permissions",
        "recommendation": "Проверить права cron-файлов, владельца root и отсутствие записи для обычных пользователей.",
    },
    "hrdn-7222": {
        "category": "Усиление системы",
        "remediation_id": "restrict_compilers",
        "recommendation": "Ограничить доступ к компиляторам для непривилегированных пользователей или удалить их с production-хоста.",
    },
}

OPENSCAP_RULE_MAPPINGS = {
    "sshd_disable_root_login": {
        "category": "SSH",
        "remediation_id": "disable_ssh_root_login",
        "recommendation": "Отключить вход root по SSH, проверить sshd_config и применить изменение после теста конфигурации.",
    },
    "sshd_disable_password_authentication": {
        "category": "SSH",
        "remediation_id": "disable_ssh_password_auth",
        "recommendation": "Отключить парольную SSH-аутентификацию после проверки доступа по ключам.",
    },
    "sshd_disable_empty_passwords": {
        "category": "SSH",
        "remediation_id": None,
        "recommendation": "Проверить PermitEmptyPasswords и учетные записи с пустым паролем вручную.",
    },
}


@dataclass
class Finding:
    id: str
    profileId: str
    title: str
    category: str
    risk: Risk
    status: Status
    source: str
    description: str
    recommendation: str
    remediationAvailable: bool
    remediationId: str | None = None
    affectedFiles: list[str] | None = None
    evidence: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(command: list[str], timeout: int = 5) -> tuple[int | None, str, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except FileNotFoundError:
        return None, "", "command not found"
    except subprocess.TimeoutExpired:
        return None, "", "command timed out"


def read_text(path: str) -> str | None:
    file_path = Path(path)
    if not file_path.exists():
        return None
    try:
        return file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def parse_os_release() -> dict[str, str]:
    data = read_text("/etc/os-release") or ""
    result: dict[str, str] = {}
    for line in data.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def get_effective_ssh_value(config: str, key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s+(.+?)\s*$", re.IGNORECASE)
    value: str | None = None
    for line in config.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            value = match.group(1).strip().lower()
    return value


def finding(
    *,
    id: str,
    profile_id: str,
    title: str,
    category: str,
    risk: Risk,
    status: Status,
    description: str,
    recommendation: str,
    remediation_available: bool,
    remediation_id: str | None = None,
    affected_files: list[str] | None = None,
    evidence: str | None = None,
    source: str = "agent",
) -> Finding:
    return Finding(
        id=id,
        profileId=profile_id,
        title=title,
        category=category,
        risk=risk,
        status=status,
        source=source,
        description=description,
        recommendation=recommendation,
        remediationAvailable=remediation_available,
        remediationId=remediation_id,
        affectedFiles=affected_files,
        evidence=evidence,
    )


def check_ssh_root_login(profile_id: str) -> Finding:
    config = read_text("/etc/ssh/sshd_config")
    if config is None:
        return finding(
            id="ssh_root_login",
            profile_id=profile_id,
            title="Проверка входа root по SSH требует ручной проверки",
            category="SSH",
            risk="info",
            status="manual",
            description="Файл /etc/ssh/sshd_config не найден или недоступен для чтения.",
            recommendation="Проверить параметр PermitRootLogin на сервере вручную.",
            remediation_available=False,
            affected_files=["/etc/ssh/sshd_config"],
            evidence="sshd_config недоступен",
        )

    value = get_effective_ssh_value(config, "PermitRootLogin")
    unsafe_values = {None, "yes", "prohibit-password", "without-password", "forced-commands-only"}
    failed = value in unsafe_values
    return finding(
        id="ssh_root_login",
        profile_id=profile_id,
        title="Разрешен или неявно допускается вход root по SSH" if failed else "Вход root по SSH отключен",
        category="SSH",
        risk="high",
        status="failed" if failed else "passed",
        description="Агент проверяет эффективное значение PermitRootLogin в sshd_config.",
        recommendation="Установить PermitRootLogin no и проверить конфигурацию командой sshd -t.",
        remediation_available=True,
        remediation_id="disable_ssh_root_login",
        affected_files=["/etc/ssh/sshd_config"],
        evidence=f"PermitRootLogin={value or 'default'}",
    )


def check_ssh_password_auth(profile_id: str) -> Finding:
    config = read_text("/etc/ssh/sshd_config")
    if config is None:
        return finding(
            id="ssh_password_auth",
            profile_id=profile_id,
            title="Проверка парольного входа SSH требует ручной проверки",
            category="SSH",
            risk="info",
            status="manual",
            description="Файл /etc/ssh/sshd_config не найден или недоступен для чтения.",
            recommendation="Проверить параметр PasswordAuthentication на сервере вручную.",
            remediation_available=False,
            affected_files=["/etc/ssh/sshd_config"],
            evidence="sshd_config недоступен",
        )

    value = get_effective_ssh_value(config, "PasswordAuthentication")
    failed = value in {None, "yes"}
    return finding(
        id="ssh_password_auth",
        profile_id=profile_id,
        title="Разрешен вход по паролю SSH" if failed else "Парольный вход SSH отключен",
        category="SSH",
        risk="high",
        status="failed" if failed else "passed",
        description="Парольная авторизация повышает риск brute-force атак.",
        recommendation="Отключить PasswordAuthentication после проверки ключевого доступа.",
        remediation_available=True,
        remediation_id="disable_ssh_password_auth",
        affected_files=["/etc/ssh/sshd_config"],
        evidence=f"PasswordAuthentication={value or 'default'}",
    )


def check_ssh_empty_passwords(profile_id: str) -> Finding:
    config = read_text("/etc/ssh/sshd_config")
    value = get_effective_ssh_value(config, "PermitEmptyPasswords") if config else None
    failed = value == "yes"
    return finding(
        id="ssh_empty_passwords",
        profile_id=profile_id,
        title="Разрешены пустые пароли SSH" if failed else "Пустые пароли SSH не разрешены или требуют проверки PAM",
        category="SSH",
        risk="medium",
        status="failed" if failed else "manual",
        description="Агент проверяет PermitEmptyPasswords, но учетные записи и PAM требуют ручной ревизии.",
        recommendation="Убедиться, что PermitEmptyPasswords no и нет локальных учетных записей с пустым паролем.",
        remediation_available=False,
        affected_files=["/etc/ssh/sshd_config", "/etc/shadow"],
        evidence=f"PermitEmptyPasswords={value or 'default/unavailable'}",
    )


def check_ufw(profile_id: str) -> Finding:
    code, stdout, stderr = run_command(["ufw", "status"], timeout=5)
    if code is None:
        return finding(
            id="ufw_disabled",
            profile_id=profile_id,
            title="UFW не установлен или недоступен",
            category="Межсетевой экран",
            risk="medium",
            status="manual",
            description="Команда ufw status недоступна. Агент не может подтвердить состояние межсетевого экрана.",
            recommendation="Проверить firewall вручную или установить и настроить UFW.",
            remediation_available=True,
            remediation_id="enable_ufw",
            evidence=stderr,
        )

    output = f"{stdout}\n{stderr}".lower()
    permission_markers = ("root", "permission", "administrator", "права", "администратор")
    if code != 0 and any(marker in output for marker in permission_markers):
        return finding(
            id="ufw_disabled",
            profile_id=profile_id,
            title="Проверка UFW требует запуска агента с правами root",
            category="Межсетевой экран",
            risk="medium",
            status="manual",
            description="Команда ufw status доступна, но отказалась возвращать статус без повышенных прав.",
            recommendation="Запустить audit-only агент с sudo или проверить статус UFW вручную.",
            remediation_available=True,
            remediation_id="enable_ufw",
            affected_files=["/etc/ufw/ufw.conf", "набор правил UFW"],
            evidence=stderr or stdout,
        )

    inactive = "inactive" in output or "неактив" in output
    active = ("active" in output or "актив" in output) and not inactive
    if not inactive and not active:
        return finding(
            id="ufw_disabled",
            profile_id=profile_id,
            title="Состояние UFW требует ручной проверки",
            category="Межсетевой экран",
            risk="medium",
            status="manual",
            description="Агент запустил ufw status, но не смог однозначно определить состояние firewall.",
            recommendation="Проверить UFW вручную и включить его при необходимости.",
            remediation_available=True,
            remediation_id="enable_ufw",
            affected_files=["/etc/ufw/ufw.conf", "набор правил UFW"],
            evidence=(stdout or stderr or f"exit={code}"),
        )

    return finding(
        id="ufw_disabled",
        profile_id=profile_id,
        title="Firewall UFW выключен" if inactive else "Firewall UFW активен",
        category="Межсетевой экран",
        risk="high",
        status="failed" if inactive else "passed",
        description="Агент проверяет статус UFW без изменения правил.",
        recommendation="Включить UFW, предварительно разрешив административный SSH-доступ.",
        remediation_available=True,
        remediation_id="enable_ufw",
        affected_files=["/etc/ufw/ufw.conf", "набор правил UFW"],
        evidence=(stdout or stderr).splitlines()[0] if (stdout or stderr) else f"exit={code}",
    )


def check_fail2ban(profile_id: str) -> Finding:
    installed = shutil.which("fail2ban-client") is not None
    return finding(
        id="fail2ban_missing",
        profile_id=profile_id,
        title="Fail2ban не установлен" if not installed else "Fail2ban установлен",
        category="Аутентификация",
        risk="medium",
        status="failed" if not installed else "passed",
        description="Агент проверяет наличие fail2ban-client в системе.",
        recommendation="Установить fail2ban и включить защитное правило для SSH.",
        remediation_available=True,
        remediation_id="install_fail2ban",
        affected_files=["/etc/fail2ban/jail.local"],
        evidence=f"fail2ban-client={'found' if installed else 'not found'}",
    )


def check_unattended_upgrades(profile_id: str) -> Finding:
    config = read_text("/etc/apt/apt.conf.d/20auto-upgrades")
    enabled = bool(config and 'APT::Periodic::Unattended-Upgrade "1"' in config)
    return finding(
        id="unattended_upgrades_disabled",
        profile_id=profile_id,
        title="Автообновления безопасности выключены" if not enabled else "Автообновления безопасности включены",
        category="Обновления",
        risk="medium",
        status="failed" if not enabled else "passed",
        description="Агент проверяет конфигурацию unattended-upgrades.",
        recommendation="Включить unattended-upgrades и согласовать политику перезагрузок.",
        remediation_available=True,
        remediation_id="enable_unattended_upgrades",
        affected_files=["/etc/apt/apt.conf.d/20auto-upgrades"],
        evidence="enabled" if enabled else "not configured",
    )


def check_updates_pending(profile_id: str) -> Finding:
    apt_check = "/usr/lib/update-notifier/apt-check"
    if not Path(apt_check).exists():
        return finding(
            id="updates_pending",
            profile_id=profile_id,
            title="Проверка обновлений требует ручной проверки",
            category="Обновления",
            risk="info",
            status="manual",
            description="На системе не найден apt-check, поэтому агент не определил количество обновлений.",
            recommendation="Выполнить apt update и проверить доступные security updates вручную.",
            remediation_available=False,
            evidence="apt-check not found",
        )

    _, stdout, stderr = run_command([apt_check], timeout=8)
    raw = stdout or stderr
    security_updates = 0
    match = re.search(r";(\d+)", raw)
    if match:
        security_updates = int(match.group(1))

    return finding(
        id="updates_pending",
        profile_id=profile_id,
        title="Есть доступные обновления безопасности" if security_updates else "Критичных обновлений безопасности не обнаружено",
        category="Обновления",
        risk="medium",
        status="manual" if security_updates else "passed",
        description="Агент проверяет счетчик security updates через apt-check.",
        recommendation="Запланировать установку обновлений и проверку сервисов после обновления.",
        remediation_available=False,
        evidence=f"apt-check={raw or 'empty'}",
    )


def check_world_writable(profile_id: str) -> Finding:
    scan_roots = ["/tmp", "/var/tmp"]
    suspicious: list[str] = []
    for root in scan_roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for path in root_path.rglob("*"):
            if len(suspicious) >= 5:
                break
            try:
                if path.is_file() and path.stat().st_mode & 0o002:
                    suspicious.append(str(path))
            except OSError:
                continue

    return finding(
        id="world_writable_files",
        profile_id=profile_id,
        title="Найдены потенциально небезопасные права на файлы" if suspicious else "World-writable файлы в базовых временных каталогах не найдены",
        category="Файловая система",
        risk="medium",
        status="manual" if suspicious else "passed",
        description="Агент выполняет ограниченную безопасную проверку /tmp и /var/tmp.",
        recommendation="Провести ручную ревизию найденных путей и ограничить права доступа при необходимости.",
        remediation_available=False,
        evidence=", ".join(suspicious) if suspicious else "no suspicious files in limited scan",
    )


def check_nginx_server_tokens(profile_id: str) -> Finding:
    nginx_conf = read_text("/etc/nginx/nginx.conf")
    if nginx_conf is None and shutil.which("nginx") is None:
        return finding(
            id="nginx_server_tokens",
            profile_id=profile_id,
            title="Nginx не обнаружен",
            category="Веб",
            risk="info",
            status="passed",
            description="Агент не нашел nginx.conf и бинарный файл nginx.",
            recommendation="Если сервер должен быть веб-сервером, установить и настроить Nginx/Apache.",
            remediation_available=False,
            evidence="nginx not found",
        )

    disabled = bool(nginx_conf and re.search(r"^\s*server_tokens\s+off\s*;", nginx_conf, re.MULTILINE))
    return finding(
        id="nginx_server_tokens",
        profile_id=profile_id,
        title="Nginx показывает версию сервера" if not disabled else "Nginx не раскрывает версию сервера",
        category="Веб",
        risk="low",
        status="failed" if not disabled else "passed",
        description="Агент проверяет директиву server_tokens в nginx.conf.",
        recommendation="Установить server_tokens off и проверить конфигурацию командой nginx -t.",
        remediation_available=True,
        remediation_id="disable_nginx_server_tokens",
        affected_files=["/etc/nginx/nginx.conf"],
        evidence="server_tokens off" if disabled else "server_tokens off not found",
    )


def check_nginx_security_headers(profile_id: str) -> Finding:
    paths = [Path("/etc/nginx/nginx.conf"), *Path("/etc/nginx/sites-enabled").glob("*")]
    readable = [path for path in paths if path.exists() and path.is_file()]
    content = "\n".join(read_text(str(path)) or "" for path in readable)
    required = ["X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
    missing = [header for header in required if header not in content]

    return finding(
        id="nginx_security_headers_missing",
        profile_id=profile_id,
        title="Не настроены базовые защитные заголовки" if missing else "Базовые защитные заголовки найдены",
        category="Веб",
        risk="medium",
        status="failed" if missing else "passed",
        description="Агент ищет базовые security headers в доступных конфигурациях Nginx.",
        recommendation="Добавить X-Frame-Options, X-Content-Type-Options и Referrer-Policy.",
        remediation_available=True,
        remediation_id="add_nginx_security_headers",
        affected_files=["/etc/nginx/snippets/security-headers.conf", "/etc/nginx/sites-enabled/*"],
        evidence=f"missing={', '.join(missing) if missing else 'none'}",
    )


def check_https(profile_id: str) -> Finding:
    configs = []
    for path in [Path("/etc/nginx/nginx.conf"), *Path("/etc/nginx/sites-enabled").glob("*")]:
        if path.exists() and path.is_file():
            configs.append(read_text(str(path)) or "")
    content = "\n".join(configs)
    has_443 = bool(re.search(r"listen\s+443", content))
    has_ssl = "ssl_certificate" in content

    return finding(
        id="https_missing",
        profile_id=profile_id,
        title="HTTPS не настроен или не обнаружен" if not (has_443 and has_ssl) else "HTTPS-конфигурация обнаружена",
        category="Веб",
        risk="high",
        status="manual" if not (has_443 and has_ssl) else "passed",
        description="Агент выполняет статическую проверку Nginx-конфигураций на listen 443 и ssl_certificate.",
        recommendation="Настроить TLS-сертификаты и перенаправление HTTP на HTTPS.",
        remediation_available=False,
        evidence=f"listen_443={has_443}, ssl_certificate={has_ssl}",
    )


def docker_command_available() -> bool:
    return shutil.which("docker") is not None


def check_docker_privileged(profile_id: str) -> Finding:
    if not docker_command_available():
        return finding(
            id="docker_privileged",
            profile_id=profile_id,
            title="Docker не обнаружен",
            category="Docker",
            risk="info",
            status="passed",
            description="Команда docker недоступна, проверка Docker-хоста пропущена.",
            recommendation="Если сервер должен быть Docker-хостом, установить Docker и повторить аудит.",
            remediation_available=False,
            evidence="docker command not found",
        )

    _, stdout, stderr = run_command(["docker", "ps", "-q"], timeout=5)
    container_ids = [line for line in stdout.splitlines() if line.strip()]
    if not container_ids:
        return finding(
            id="docker_privileged",
            profile_id=profile_id,
            title="Запущенные Docker-контейнеры не найдены",
            category="Docker",
            risk="info",
            status="passed",
            description="Агент не нашел запущенных контейнеров для проверки privileged-режима.",
            recommendation="Повторить проверку при запущенных контейнерах.",
            remediation_available=False,
            evidence=stderr or "no running containers",
        )

    privileged: list[str] = []
    for container_id in container_ids[:20]:
        _, inspect_out, _ = run_command(["docker", "inspect", "-f", "{{.HostConfig.Privileged}} {{.Name}}", container_id], timeout=5)
        if inspect_out.startswith("true"):
            privileged.append(inspect_out)

    return finding(
        id="docker_privileged",
        profile_id=profile_id,
        title="Есть privileged Docker-контейнеры" if privileged else "Privileged Docker-контейнеры не найдены",
        category="Docker",
        risk="high",
        status="manual" if privileged else "passed",
        description="Агент проверяет HostConfig.Privileged у запущенных контейнеров.",
        recommendation="Пересмотреть контейнеры и убрать privileged там, где это не требуется.",
        remediation_available=False,
        evidence=", ".join(privileged) if privileged else "none",
    )


def check_docker_socket(profile_id: str) -> Finding:
    if not docker_command_available():
        return finding(
            id="docker_socket_mounted",
            profile_id=profile_id,
            title="Docker socket не проверялся",
            category="Docker",
            risk="info",
            status="passed",
            description="Команда docker недоступна, проверка docker.sock пропущена.",
            recommendation="Если сервер должен быть Docker-хостом, установить Docker и повторить аудит.",
            remediation_available=False,
            evidence="docker command not found",
        )

    _, stdout, _ = run_command(["docker", "ps", "-q"], timeout=5)
    mounted: list[str] = []
    for container_id in [line for line in stdout.splitlines() if line.strip()][:20]:
        _, inspect_out, _ = run_command(["docker", "inspect", "-f", "{{.Name}} {{json .Mounts}}", container_id], timeout=5)
        if "/var/run/docker.sock" in inspect_out:
            mounted.append(inspect_out.split(" ", 1)[0])

    return finding(
        id="docker_socket_mounted",
        profile_id=profile_id,
        title="Docker socket проброшен в контейнер" if mounted else "Проброс docker.sock не найден",
        category="Docker",
        risk="high",
        status="manual" if mounted else "passed",
        description="Агент ищет монтирование /var/run/docker.sock в запущенных контейнерах.",
        recommendation="Удалить монтирование docker.sock или заменить его на ограниченный proxy.",
        remediation_available=False,
        evidence=", ".join(mounted) if mounted else "none",
    )


def check_docker_root_user(profile_id: str) -> Finding:
    if not docker_command_available():
        return finding(
            id="docker_root_user",
            profile_id=profile_id,
            title="Пользователь контейнеров не проверялся",
            category="Docker",
            risk="info",
            status="passed",
            description="Команда docker недоступна, проверка пользователей контейнеров пропущена.",
            recommendation="Если сервер должен быть Docker-хостом, установить Docker и повторить аудит.",
            remediation_available=False,
            evidence="docker command not found",
        )

    _, stdout, _ = run_command(["docker", "ps", "-q"], timeout=5)
    root_containers: list[str] = []
    for container_id in [line for line in stdout.splitlines() if line.strip()][:20]:
        _, inspect_out, _ = run_command(["docker", "inspect", "-f", "{{.Config.User}} {{.Name}}", container_id], timeout=5)
        user, _, name = inspect_out.partition(" ")
        if user in {"", "0", "root"}:
            root_containers.append(name or container_id)

    return finding(
        id="docker_root_user",
        profile_id=profile_id,
        title="Контейнеры запущены от root" if root_containers else "Контейнеры с root-пользователем не найдены",
        category="Docker",
        risk="medium",
        status="manual" if root_containers else "passed",
        description="Агент проверяет Config.User у запущенных контейнеров.",
        recommendation="Добавить USER в Dockerfile или user в compose-конфигурацию.",
        remediation_available=False,
        evidence=", ".join(root_containers) if root_containers else "none",
    )


def normalize_lynis_line(line: str) -> str:
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    return line.strip(" \t-*")


def get_lynis_report_paths(custom_path: str | None = None) -> list[Path]:
    paths: list[Path] = []
    if custom_path:
        paths.append(Path(custom_path).expanduser())
    env_path = os.environ.get("LYNIS_REPORT_PATH")
    if env_path:
        paths.append(Path(env_path).expanduser())
    paths.extend([Path("/var/log/lynis-report.dat"), Path.home() / "lynis-report.dat", Path.cwd() / "lynis-report.dat"])

    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def snapshot_file_mtimes(paths: list[Path]) -> dict[str, float | None]:
    result: dict[str, float | None] = {}
    for path in paths:
        try:
            result[str(path)] = path.stat().st_mtime
        except OSError:
            result[str(path)] = None
    return result


def read_updated_lynis_report(paths: list[Path], before: dict[str, float | None]) -> tuple[str | None, str | None]:
    candidates: list[tuple[float, Path]] = []
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        previous = before.get(str(path))
        if previous is None or stat.st_mtime > previous:
            candidates.append((stat.st_mtime, path))

    for _, path in sorted(candidates, reverse=True):
        content = read_text(str(path))
        if content:
            return content, str(path)
    return None, None


def extract_lynis_test_id(text: str, parts: list[str]) -> str | None:
    patterns = [
        re.compile(r"\[([A-Z0-9]{4}-[0-9]{4})\]", re.IGNORECASE),
        re.compile(r"\b([A-Z0-9]{4}-[0-9]{4})\b", re.IGNORECASE),
    ]
    for value in [text, *parts]:
        for pattern in patterns:
            match = pattern.search(value)
            if match:
                return match.group(1).lower()
    return None


def lynis_finding_id(test_id: str | None, index: int) -> str:
    if test_id:
        return f"lynis_{test_id}"
    return f"lynis_item_{index:03d}"


def get_lynis_category(test_id: str | None) -> str:
    if not test_id:
        return "Lynis"
    exact = LYNIS_TEST_MAPPINGS.get(test_id)
    if exact:
        return str(exact["category"])
    prefix = test_id.split("-", 1)[0]
    return LYNIS_PREFIX_CATEGORIES.get(prefix, "Lynis")


def build_lynis_finding(
    *,
    profile_id: str,
    title: str,
    risk: Risk,
    test_id: str | None,
    index: int,
    description: str,
    evidence: str,
) -> Finding:
    exact = LYNIS_TEST_MAPPINGS.get(test_id or "")
    remediation_id = str(exact["remediation_id"]) if exact else None
    recommendation = (
        str(exact["recommendation"])
        if exact
        else "Проверить test-id в отчете Lynis, оценить влияние на сервер и добавить действие в план исправлений."
    )
    return finding(
        id=lynis_finding_id(test_id, index),
        profile_id=profile_id,
        title=f"Lynis: {title}",
        category=get_lynis_category(test_id),
        risk=risk,
        status="manual",
        description=description,
        recommendation=recommendation,
        remediation_available=remediation_id is not None,
        remediation_id=remediation_id,
        evidence=evidence,
        source="lynis",
    )


def parse_lynis_findings(profile_id: str, output: str, limit: int = 30) -> list[Finding]:
    results: list[Finding] = []
    seen: set[str] = set()
    warning_pattern = re.compile(r"\[\s*WARNING\s*\]\s*:?\s*(.+)", re.IGNORECASE)
    suggestion_pattern = re.compile(r"\[\s*SUGGESTION\s*\]\s*:?\s*(.+)", re.IGNORECASE)

    for raw_line in output.splitlines():
        line = normalize_lynis_line(raw_line)
        if not line:
            continue

        risk: Risk | None = None
        title = ""
        match = warning_pattern.search(line)
        if match:
            risk = "high"
            title = match.group(1).strip()
        else:
            match = suggestion_pattern.search(line)
            if match:
                risk = "medium"
                title = match.group(1).strip()

        if risk is None or not title:
            continue

        test_id = extract_lynis_test_id(title, [])
        finding_id = lynis_finding_id(test_id, len(results) + 1)
        if finding_id in seen:
            continue

        seen.add(finding_id)
        results.append(
            build_lynis_finding(
                profile_id=profile_id,
                title=title,
                risk=risk,
                test_id=test_id,
                index=len(results) + 1,
                description="Lynis обнаружил предупреждение или рекомендацию, которую нужно проверить администратору.",
                evidence=line,
            ),
        )
        if len(results) >= limit:
            break

    return results


def parse_lynis_report_dat(profile_id: str, content: str, source_path: str, limit: int = 50) -> list[Finding]:
    results: list[Finding] = []
    seen: set[str] = set()
    key_map: dict[str, tuple[Risk, str]] = {
        "warning[]": ("high", "предупреждение"),
        "suggestion[]": ("medium", "рекомендация"),
    }

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in key_map:
            continue

        risk, kind = key_map[key]
        parts = [part.strip() for part in value.split("|") if part.strip()]
        title = parts[0] if parts else value.strip()
        test_id = extract_lynis_test_id(title, parts)
        finding_id = lynis_finding_id(test_id, len(results) + 1)
        if finding_id in seen:
            continue

        seen.add(finding_id)
        results.append(
            build_lynis_finding(
                profile_id=profile_id,
                title=title,
                risk=risk,
                test_id=test_id,
                index=len(results) + 1,
                description=f"Lynis report.dat содержит {kind}, требующее проверки администратором.",
                evidence=f"{source_path}: {line}",
            ),
        )
        if len(results) >= limit:
            break

    return results


def run_lynis_checks(profile_id: str, timeout: int = 120, report_path: str | None = None) -> list[Finding]:
    lynis_path = shutil.which("lynis")
    if lynis_path is None:
        return [
            finding(
                id="lynis_not_installed",
                profile_id=profile_id,
                title="Lynis не установлен",
                category="Lynis",
                risk="info",
                status="manual",
                description="Расширенный аудит Lynis запрошен, но команда lynis не найдена в системе.",
                recommendation="Установить Lynis через пакетный менеджер и повторить аудит с флагом --include-lynis.",
                remediation_available=False,
                evidence="command not found",
                source="lynis",
            ),
        ]

    report_paths = get_lynis_report_paths(report_path)
    report_mtimes = snapshot_file_mtimes(report_paths)
    code, stdout, stderr = run_command([lynis_path, "audit", "system", "--no-colors", "--quiet"], timeout=timeout)
    output = "\n".join(part for part in [stdout, stderr] if part)
    report_content, report_source = read_updated_lynis_report(report_paths, report_mtimes)
    if report_content and report_source:
        parsed_report = parse_lynis_report_dat(profile_id, report_content, report_source)
        if parsed_report:
            return parsed_report

    parsed = parse_lynis_findings(profile_id, output)
    if parsed:
        return parsed

    return [
        finding(
            id="lynis_completed",
            profile_id=profile_id,
            title="Lynis выполнен, предупреждения не извлечены",
            category="Lynis",
            risk="info",
            status="passed" if code == 0 else "manual",
            description="Агент запустил Lynis, но не нашел строк WARNING/SUGGESTION в выводе.",
            recommendation="При необходимости изучить полный вывод Lynis на хосте или запустить Lynis вручную.",
            remediation_available=False,
            evidence=f"exit={code}, output_lines={len(output.splitlines())}",
            source="lynis",
        ),
    ]


def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def slugify_id(value: str) -> str:
    slug = re.sub(r"^xccdf_org\.ssgproject\.content_rule_", "", value)
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", slug).strip("_").lower()
    return slug or "unknown_rule"


def get_openscap_profile(custom_profile: str | None = None) -> str:
    return custom_profile or os.environ.get("OPENSCAP_PROFILE") or "xccdf_org.ssgproject.content_profile_cis_level1_server"


def openscap_content_candidates(custom_path: str | None = None, os_release: dict[str, str] | None = None) -> list[Path]:
    release = os_release or parse_os_release()
    paths: list[Path] = []
    if custom_path:
        paths.append(Path(custom_path).expanduser())
    env_path = os.environ.get("OPENSCAP_CONTENT_PATH")
    if env_path:
        paths.append(Path(env_path).expanduser())

    os_id = release.get("ID", "").lower()
    version = re.sub(r"\D", "", release.get("VERSION_ID", ""))
    id_like = release.get("ID_LIKE", "").lower().split()
    content_dir = Path("/usr/share/xml/scap/ssg/content")
    names: list[str] = []
    if os_id and version:
        names.append(f"ssg-{os_id}{version}-ds.xml")
    if os_id:
        names.append(f"ssg-{os_id}-ds.xml")
    for like in id_like:
        if like and version:
            names.append(f"ssg-{like}{version[:1]}-ds.xml")
        if like:
            names.append(f"ssg-{like}-ds.xml")
    names.extend(
        [
            "ssg-ubuntu2404-ds.xml",
            "ssg-ubuntu2204-ds.xml",
            "ssg-debian12-ds.xml",
            "ssg-rhel9-ds.xml",
            "ssg-rhel8-ds.xml",
        ],
    )
    paths.extend(content_dir / name for name in names)

    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def find_openscap_content_path(custom_path: str | None = None, os_release: dict[str, str] | None = None) -> Path | None:
    for path in openscap_content_candidates(custom_path, os_release):
        if path.exists() and path.is_file():
            return path
    return None


def openscap_category(rule_id: str) -> str:
    slug = slugify_id(rule_id)
    for marker, category in [
        ("sshd", "SSH"),
        ("ssh", "SSH"),
        ("firewall", "Межсетевой экран"),
        ("ufw", "Межсетевой экран"),
        ("audit", "Журналирование"),
        ("sysctl", "Ядро"),
        ("kernel", "Ядро"),
        ("password", "Учетные записи"),
        ("account", "Учетные записи"),
        ("file", "Файловая система"),
        ("permission", "Файловая система"),
        ("package", "Пакеты"),
        ("aide", "Контроль целостности"),
    ]:
        if marker in slug:
            return category
    return "OpenSCAP"


def get_openscap_rule_mapping(rule_id: str) -> dict[str, object] | None:
    slug = slugify_id(rule_id)
    for marker, mapping in OPENSCAP_RULE_MAPPINGS.items():
        if marker in slug:
            return mapping
    return None


def text_from_child(element: ET.Element, child_name: str) -> str | None:
    for child in element:
        if xml_local_name(child.tag) == child_name and child.text:
            return child.text.strip()
    return None


def collect_openscap_rule_titles(root: ET.Element) -> dict[str, str]:
    titles: dict[str, str] = {}
    for element in root.iter():
        if xml_local_name(element.tag) != "Rule":
            continue
        rule_id = element.attrib.get("id")
        title = text_from_child(element, "title")
        if rule_id and title:
            titles[rule_id] = title
    return titles


def risk_from_openscap_severity(severity: str | None) -> Risk:
    value = (severity or "").lower()
    if value == "high":
        return "high"
    if value == "medium":
        return "medium"
    if value == "low":
        return "low"
    return "info"


def build_openscap_finding(
    *,
    profile_id: str,
    rule_id: str,
    title: str,
    result: str,
    severity: str | None,
    source_path: str,
) -> Finding:
    mapping = get_openscap_rule_mapping(rule_id)
    remediation_id = str(mapping["remediation_id"]) if mapping and mapping.get("remediation_id") else None
    category = str(mapping["category"]) if mapping and mapping.get("category") else openscap_category(rule_id)
    recommendation = (
        str(mapping["recommendation"])
        if mapping and mapping.get("recommendation")
        else "Открыть правило SCAP Security Guide, оценить применимость к хосту и добавить действие в план исправлений."
    )
    slug = slugify_id(rule_id)
    return finding(
        id=f"openscap_{slug}",
        profile_id=profile_id,
        title=f"OpenSCAP: {title}",
        category=category,
        risk=risk_from_openscap_severity(severity),
        status="manual",
        description="OpenSCAP/SCAP Security Guide обнаружил несоответствие выбранному XCCDF-профилю.",
        recommendation=recommendation,
        remediation_available=remediation_id is not None,
        remediation_id=remediation_id,
        evidence=f"{source_path}: rule={rule_id}, result={result}, severity={severity or 'unknown'}",
        source="openscap",
    )


def parse_openscap_results(profile_id: str, content: str, source_path: str, limit: int = 80) -> list[Finding]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []

    titles = collect_openscap_rule_titles(root)
    results: list[Finding] = []
    seen: set[str] = set()
    actionable_results = {"fail", "error"}

    for element in root.iter():
        if xml_local_name(element.tag) != "rule-result":
            continue
        rule_id = element.attrib.get("idref", "")
        result = (text_from_child(element, "result") or "").lower()
        if not rule_id or result not in actionable_results:
            continue
        finding_id = f"openscap_{slugify_id(rule_id)}"
        if finding_id in seen:
            continue

        seen.add(finding_id)
        severity = element.attrib.get("severity")
        fallback_title = slugify_id(rule_id).replace("_", " ")
        results.append(
            build_openscap_finding(
                profile_id=profile_id,
                rule_id=rule_id,
                title=titles.get(rule_id, fallback_title),
                result=result,
                severity=severity,
                source_path=source_path,
            ),
        )
        if len(results) >= limit:
            break
    return results


def run_openscap_checks(
    profile_id: str,
    timeout: int = 240,
    content_path: str | None = None,
    oscap_profile: str | None = None,
) -> list[Finding]:
    oscap_path = shutil.which("oscap")
    if oscap_path is None:
        return [
            finding(
                id="openscap_not_installed",
                profile_id=profile_id,
                title="OpenSCAP не установлен",
                category="OpenSCAP",
                risk="info",
                status="manual",
                description="Расширенный аудит OpenSCAP запрошен, но команда oscap не найдена в системе.",
                recommendation="Установить openscap-scanner и SCAP Security Guide, затем повторить аудит с флагом --include-openscap.",
                remediation_available=False,
                evidence="command not found",
                source="openscap",
            ),
        ]

    os_release = parse_os_release()
    content = find_openscap_content_path(content_path, os_release)
    if content is None:
        candidates = ", ".join(str(path) for path in openscap_content_candidates(content_path, os_release)[:6])
        return [
            finding(
                id="openscap_content_not_found",
                profile_id=profile_id,
                title="SCAP Security Guide datastream не найден",
                category="OpenSCAP",
                risk="info",
                status="manual",
                description="OpenSCAP установлен, но агент не нашел XML datastream с правилами SCAP Security Guide.",
                recommendation="Установить пакет SCAP Security Guide или указать путь через --openscap-content-path.",
                remediation_available=False,
                evidence=f"checked={candidates}",
                source="openscap",
            ),
        ]

    profile = get_openscap_profile(oscap_profile)
    with tempfile.TemporaryDirectory(prefix="hcp-openscap-") as temp_dir:
        results_path = Path(temp_dir) / "results.xml"
        report_path = Path(temp_dir) / "report.html"
        command = [
            oscap_path,
            "xccdf",
            "eval",
            "--profile",
            profile,
            "--results",
            str(results_path),
            "--report",
            str(report_path),
            str(content),
        ]
        code, stdout, stderr = run_command(command, timeout=timeout)
        if results_path.exists():
            parsed = parse_openscap_results(profile_id, read_text(str(results_path)) or "", str(content))
            if parsed:
                return parsed

        return [
            finding(
                id="openscap_completed",
                profile_id=profile_id,
                title="OpenSCAP выполнен, несоответствия не извлечены",
                category="OpenSCAP",
                risk="info",
                status="passed" if code in {0, 2} else "manual",
                description="Агент запустил OpenSCAP, но не нашел failed/error rule-result в XML-результатах.",
                recommendation="Проверить выбранный XCCDF-профиль и полный HTML/XML-отчет OpenSCAP на хосте.",
                remediation_available=False,
                evidence=f"exit={code}, profile={profile}, content={content}, stdout_lines={len(stdout.splitlines())}, stderr={stderr[:240]}",
                source="openscap",
            ),
        ]


def checks_for_profile(profile_id: str) -> list[Finding]:
    basic = [
        check_ufw(profile_id),
        check_fail2ban(profile_id),
        check_updates_pending(profile_id),
        check_unattended_upgrades(profile_id),
        check_world_writable(profile_id),
    ]
    ssh = [
        check_ssh_root_login(profile_id),
        check_ssh_password_auth(profile_id),
        check_ssh_empty_passwords(profile_id),
    ]
    web = [
        check_nginx_server_tokens(profile_id),
        check_nginx_security_headers(profile_id),
        check_https(profile_id),
    ]
    docker = [
        check_docker_privileged(profile_id),
        check_docker_socket(profile_id),
        check_docker_root_user(profile_id),
    ]

    if profile_id == "ssh_security":
        return ssh
    if profile_id == "web_server":
        return web
    if profile_id == "docker_host":
        return docker
    return basic + ssh


def build_summary(findings: list[Finding]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0, "info": 0}
    weights = {"high": 20, "medium": 10, "low": 4, "info": 1}
    penalty = 0
    for item in findings:
        if item.status in {"passed", "fixed"}:
            continue
        summary[item.risk] += 1
        penalty += weights[item.risk]
    summary["score"] = max(0, min(100, 100 - penalty))
    return summary


def run_audit(
    profile_id: str,
    include_lynis: bool = False,
    lynis_timeout: int = 120,
    lynis_report_path: str | None = None,
    include_openscap: bool = False,
    openscap_timeout: int = 240,
    openscap_content_path: str | None = None,
    openscap_profile: str | None = None,
) -> dict[str, object]:
    os_release = parse_os_release()
    findings = checks_for_profile(profile_id)
    if include_lynis:
        findings.extend(run_lynis_checks(profile_id, timeout=lynis_timeout, report_path=lynis_report_path))
    if include_openscap:
        findings.extend(
            run_openscap_checks(
                profile_id,
                timeout=openscap_timeout,
                content_path=openscap_content_path,
                oscap_profile=openscap_profile,
            ),
        )

    lynis_findings = [item for item in findings if item.source == "lynis"]
    openscap_findings = [item for item in findings if item.source == "openscap"]
    return {
        "auditId": f"agent_audit_{profile_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "createdAt": utc_now(),
        "hostname": socket.gethostname(),
        "os": os_release.get("PRETTY_NAME", os_release.get("NAME", "Unknown Linux")),
        "profileId": profile_id,
        "mode": "agent",
        "agent": {
            "version": "0.3.0",
            "safeMode": True,
            "remediationEnabled": False,
            "user": os.environ.get("USER", "unknown"),
            "integrations": {
                "lynis": {
                    "enabled": include_lynis,
                    "findings": len(lynis_findings),
                    "reportPath": lynis_report_path,
                },
                "openscap": {
                    "enabled": include_openscap,
                    "findings": len(openscap_findings),
                    "contentPath": openscap_content_path,
                    "profile": openscap_profile or os.environ.get("OPENSCAP_PROFILE"),
                },
            },
        },
        "summary": build_summary(findings),
        "findings": [asdict(item) for item in findings],
    }


def no_op_response(command: str, args: argparse.Namespace) -> dict[str, object]:
    return {
        "status": "not_implemented",
        "command": command,
        "createdAt": utc_now(),
        "message": "Первая версия агента поддерживает только безопасный audit-only режим. Изменения ОС не выполняются.",
        "audit": args.audit,
        "remediation": args.remediation,
        "backup": args.backup,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Hardening Control Platform Linux Agent")
    parser.add_argument("command", choices=["audit", "remediate", "rollback"])
    parser.add_argument("--profile", default="basic_linux")
    parser.add_argument("--audit")
    parser.add_argument("--remediation")
    parser.add_argument("--backup")
    parser.add_argument("--include-lynis", action="store_true", help="Run optional Lynis audit if lynis is installed")
    parser.add_argument("--lynis-timeout", type=int, default=120, help="Timeout for optional Lynis audit in seconds")
    parser.add_argument("--lynis-report-path", help="Optional path to Lynis report.dat for parsing")
    parser.add_argument("--include-openscap", action="store_true", help="Run optional OpenSCAP audit if oscap and SSG are installed")
    parser.add_argument("--openscap-timeout", type=int, default=240, help="Timeout for optional OpenSCAP audit in seconds")
    parser.add_argument("--openscap-content-path", help="Optional path to SCAP Security Guide datastream XML")
    parser.add_argument("--openscap-profile", help="Optional XCCDF profile id for OpenSCAP")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    if args.command == "audit":
        payload = run_audit(
            args.profile,
            include_lynis=args.include_lynis,
            lynis_timeout=args.lynis_timeout,
            lynis_report_path=args.lynis_report_path,
            include_openscap=args.include_openscap,
            openscap_timeout=args.openscap_timeout,
            openscap_content_path=args.openscap_content_path,
            openscap_profile=args.openscap_profile,
        )
    else:
        payload = no_op_response(args.command, args)

    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
