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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Risk = Literal["high", "medium", "low", "info"]
Status = Literal["failed", "passed", "fixed", "manual"]


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
) -> Finding:
    return Finding(
        id=id,
        profileId=profile_id,
        title=title,
        category=category,
        risk=risk,
        status=status,
        source="agent",
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
    if code != 0 and ("root" in output or "permission" in output):
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

    inactive = "inactive" in output
    active = "active" in output and not inactive
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


def run_audit(profile_id: str) -> dict[str, object]:
    os_release = parse_os_release()
    findings = checks_for_profile(profile_id)
    return {
        "auditId": f"agent_audit_{profile_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "createdAt": utc_now(),
        "hostname": socket.gethostname(),
        "os": os_release.get("PRETTY_NAME", os_release.get("NAME", "Unknown Linux")),
        "profileId": profile_id,
        "mode": "agent",
        "agent": {
            "version": "0.1.0",
            "safeMode": True,
            "remediationEnabled": False,
            "user": os.environ.get("USER", "unknown"),
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
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    if args.command == "audit":
        payload = run_audit(args.profile)
    else:
        payload = no_op_response(args.command, args)

    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
