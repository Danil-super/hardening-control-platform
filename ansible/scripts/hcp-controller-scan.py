#!/usr/bin/env python3
"""Central-only scanner adapters for Hardening Control Platform.

The script is executed on the Ansible control node.  It never installs or
starts a persistent service on a managed host.  The Lynis parser consumes a
report that a dedicated, temporary Ansible run has already retrieved.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as element_tree
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(command: list[str], timeout: int) -> tuple[int | None, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return None, "", f"Не найдена команда: {command[0]}"
    except subprocess.TimeoutExpired:
        return None, "", f"Превышено время выполнения ({timeout} с)."
    except OSError as error:
        return None, "", str(error)


def finding(
    *,
    identifier: str,
    title: str,
    risk: str,
    status: str,
    source: str,
    description: str,
    recommendation: str,
    evidence: str = "",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "profileId": source,
        "title": title,
        "category": "Внешняя проверка",
        "risk": risk,
        "status": status,
        "source": source,
        "description": description,
        "recommendation": recommendation,
        "remediationAvailable": False,
        "remediationId": None,
        "affectedFiles": [],
        "evidence": evidence[:3000],
    }


def summarize(findings: list[dict[str, Any]]) -> dict[str, int | None]:
    failed = [item for item in findings if item["status"] == "failed"]
    return {
        "score": None,
        "high": sum(item["risk"] == "high" for item in failed),
        "medium": sum(item["risk"] == "medium" for item in failed),
        "low": sum(item["risk"] == "low" for item in failed),
        "info": sum(item["risk"] == "info" for item in findings),
        "total": len(findings),
    }


def base_report(args: argparse.Namespace, mode: str, source: str, findings: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    summary = summarize(findings)
    # Lynis publishes its own 0–100 hardening index. Keep it in summary.score
    # as well so every report consumer can display it, but preserve the raw
    # scanner field below for provenance.
    if mode == "lynis" and isinstance(extra.get("hardeningIndex"), int):
        summary["score"] = extra["hardeningIndex"]
    return {
        "schemaVersion": 1,
        "action": mode,
        "runId": args.run_id,
        "inventoryHost": args.inventory_host,
        "createdAt": now(),
        "hostname": args.inventory_host,
        "os": None,
        "profileId": mode,
        "mode": mode,
        "scanner": {"source": source, **extra},
        "summary": summary,
        "findings": findings,
        "events": [],
    }


def unavailable(args: argparse.Namespace, mode: str, source: str, tool: str) -> dict[str, Any]:
    return base_report(
        args,
        mode,
        source,
        [finding(
            identifier=f"{mode}_tool_missing",
            title=f"{tool} не установлен на управляющей машине",
            risk="info",
            status="manual",
            source=source,
            description="Проверка не запускалась: на control node отсутствует необходимая программа.",
            recommendation=f"Установите {tool} только на control node и повторите запуск.",
        )],
        available=False,
    )


def algorithm_names(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    return [str(item.get("name")) for item in items if isinstance(item, dict) and item.get("name")]


def ssh_audit(args: argparse.Namespace) -> dict[str, Any]:
    binary = os.environ.get("HCP_SSH_AUDIT_BIN", "ssh-audit")
    if not shutil.which(binary):
        return unavailable(args, "ssh-audit", "ssh_audit", "ssh-audit")

    code, stdout, stderr = run([binary, "--json", "--skip-rate-test", "-p", str(args.port), args.host], 90)
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return base_report(
            args,
            "ssh-audit",
            "ssh_audit",
            [finding(
                identifier="ssh_audit_execution_error",
                title="Не удалось получить результат SSH crypto-аудита",
                risk="info",
                status="manual",
                source="ssh_audit",
                description="ssh-audit не вернул корректный JSON. Целевой SSH-сервис не изменялся.",
                recommendation="Проверьте доступность SSH-порта и журнал control node.",
                evidence=(stderr or stdout or f"exit={code}"),
            )],
            available=True,
            target=f"{args.host}:{args.port}",
            exitCode=code,
        )

    findings: list[dict[str, Any]] = []
    recommendations = payload.get("recommendations", {}) if isinstance(payload, dict) else {}
    severity_map = (("critical", "high"), ("warning", "medium"))
    for recommendation_level, risk in severity_map:
        delete_items = recommendations.get(recommendation_level, {}).get("del", {}) if isinstance(recommendations, dict) else {}
        if not isinstance(delete_items, dict):
            continue
        for algorithm_kind, algorithms in delete_items.items():
            names = algorithm_names(algorithms)
            if not names:
                continue
            findings.append(finding(
                identifier=f"ssh_audit_{recommendation_level}_{algorithm_kind}",
                title=f"SSH предлагает отключить алгоритмы ({algorithm_kind})",
                risk=risk,
                status="failed",
                source="ssh_audit",
                description="Набор алгоритмов SSH не соответствует рекомендациям ssh-audit.",
                recommendation="Сверьте совместимость клиентов, затем исключите алгоритмы через централизованный SSH hardening-playbook.",
                evidence=", ".join(names),
            ))

    cves = payload.get("cves", []) if isinstance(payload, dict) else []
    if isinstance(cves, list) and cves:
        findings.append(finding(
            identifier="ssh_audit_cves",
            title="SSH-аудит сообщил об известных CVE",
            risk="high",
            status="failed",
            source="ssh_audit",
            description="SSH-сервис или его криптографическая конфигурация связаны с известными CVE.",
            recommendation="Проверьте версию OpenSSH у поставщика ОС и установите доступные security updates.",
            evidence=", ".join(str(value) for value in cves),
        ))

    notes = payload.get("additional_notes", []) if isinstance(payload, dict) else []
    if isinstance(notes, list) and notes:
        findings.append(finding(
            identifier="ssh_audit_notes",
            title="SSH-аудит требует ручной оценки совместимости",
            risk="info",
            status="manual",
            source="ssh_audit",
            description="Не все рекомендации можно применять без учета используемых SSH-клиентов.",
            recommendation="Перед изменением алгоритмов проверьте доступ администраторов и автоматизации.",
            evidence=" ".join(str(value) for value in notes),
        ))

    if not any(item["status"] == "failed" for item in findings):
        findings.append(finding(
            identifier="ssh_audit_no_blocking_findings",
            title="SSH crypto-аудит не выявил блокирующих рекомендаций",
            risk="info",
            status="passed",
            source="ssh_audit",
            description="Проверена только сетевая криптографическая витрина SSH-сервера.",
            recommendation="Регулярно повторяйте проверку после обновления OpenSSH или изменения sshd_config.",
        ))

    banner = payload.get("banner", {}) if isinstance(payload, dict) else {}
    return base_report(
        args,
        "ssh-audit",
        "ssh_audit",
        findings,
        available=True,
        target=payload.get("target", f"{args.host}:{args.port}"),
        banner=banner,
        exitCode=code,
    )


def port_risk(port: int) -> str:
    if port in {21, 23, 110, 143, 445, 3389}:
        return "high"
    if port in {25, 53, 111, 139, 2049, 2375, 3306, 5432, 6379}:
        return "medium"
    return "info"


def nmap(args: argparse.Namespace) -> dict[str, Any]:
    binary = os.environ.get("HCP_NMAP_BIN", "nmap")
    if not shutil.which(binary):
        return unavailable(args, "nmap", "nmap", "nmap")

    command = [binary, "-Pn", "-n", "-sT", "-sV", "--version-light", "--top-ports", "100", "-oX", "-", args.host]
    code, stdout, stderr = run(command, 180)
    try:
        root = element_tree.fromstring(stdout)
    except element_tree.ParseError:
        return base_report(
            args,
            "nmap",
            "nmap",
            [finding(
                identifier="nmap_execution_error",
                title="Не удалось получить результат сетевого сканирования",
                risk="info",
                status="manual",
                source="nmap",
                description="Nmap не вернул корректный XML. Сканирование выполнялось только с control node.",
                recommendation="Проверьте маршрут, firewall и доступность целевого узла.",
                evidence=(stderr or stdout or f"exit={code}"),
            )],
            available=True,
            target=args.host,
            exitCode=code,
        )

    findings: list[dict[str, Any]] = []
    host = root.find("host")
    if host is None or host.find("status") is None or host.find("status").get("state") != "up":
        findings.append(finding(
            identifier="nmap_host_unreachable",
            title="Nmap не подтвердил доступность хоста",
            risk="info",
            status="manual",
            source="nmap",
            description="Сканирование завершилось, но узел не ответил как доступный.",
            recommendation="Проверьте адрес, маршрутизацию и правила firewall.",
            evidence=f"exit={code}",
        ))
    else:
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = int(port.get("portid", "0"))
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            risk = port_risk(number)
            findings.append(finding(
                identifier=f"nmap_open_{protocol}_{number}",
                title=f"Открыт {protocol}/{number} ({service_name})",
                risk=risk,
                status="failed" if risk != "info" else "manual",
                source="nmap",
                description="Сервис доступен из сети управления. Открытие порта требует осознанного обоснования.",
                recommendation="Подтвердите необходимость сервиса, ограничьте источники доступа и отключите неиспользуемые службы.",
                evidence=f"service={service_name}; product={product}; version={version}",
            ))
        if not findings:
            findings.append(finding(
                identifier="nmap_no_open_top_ports",
                title="В top-100 TCP-портах открытые сервисы не обнаружены",
                risk="info",
                status="passed",
                source="nmap",
                description="Это не заменяет полный инвентарь сервисов и проверку firewall на самом сервере.",
                recommendation="Используйте SSH-аудит для проверки локальных сокетов и правил firewall.",
            ))

    return base_report(args, "nmap", "nmap", findings, available=True, target=args.host, exitCode=code)


def values_from_lynis_report(content: str, key: str) -> list[str]:
    prefix = f"{key}[]="
    return [line[len(prefix):].strip() for line in content.splitlines() if line.startswith(prefix)]


def lynis_report(args: argparse.Namespace) -> dict[str, Any]:
    try:
        content = Path(args.input).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        content = ""
        read_error = str(error)
    else:
        read_error = ""

    findings: list[dict[str, Any]] = []
    for value in values_from_lynis_report(content, "warning")[:60]:
        rule, _, detail = value.partition("|")
        findings.append(finding(
            identifier=f"lynis_warning_{rule or len(findings)}",
            title=f"Lynis warning: {rule or value}",
            risk="medium",
            status="failed",
            source="lynis",
            description="Lynis отметил настройку, которую необходимо проверить перед исправлением.",
            recommendation="Оцените рекомендацию Lynis, влияние на роль сервера и применяйте изменение отдельным approval-playbook.",
            evidence=detail or value,
        ))
    for value in values_from_lynis_report(content, "suggestion")[:60]:
        rule, _, detail = value.partition("|")
        findings.append(finding(
            identifier=f"lynis_suggestion_{rule or len(findings)}",
            title=f"Lynis suggestion: {rule or value}",
            risk="low",
            status="manual",
            source="lynis",
            description="Lynis предложил дополнительное усиление конфигурации.",
            recommendation="Проверьте применимость рекомендации для этой роли сервера.",
            evidence=detail or value,
        ))

    if args.exit_code != 0:
        findings.append(finding(
            identifier="lynis_nonzero_exit",
            title="Lynis завершился с ненулевым кодом",
            risk="info",
            status="manual",
            source="lynis",
            description="Отчет может содержать частичные результаты; автоматическое применение рекомендаций недопустимо.",
            recommendation="Проверьте журнал выполнения и повторите аудит после устранения причины ошибки.",
            evidence=f"exit={args.exit_code}",
        ))

    hardening_index = None
    for line in content.splitlines():
        if line.startswith("hardening_index="):
            try:
                hardening_index = int(line.split("=", 1)[1].strip())
            except ValueError:
                pass
            break

    if read_error or not content:
        findings.append(finding(
            identifier="lynis_no_report",
            title="Lynis не сформировал отчет",
            risk="info",
            status="manual",
            source="lynis",
            description="Временный запуск завершился без машиночитаемого отчета.",
            recommendation="Проверьте sudo-доступ и журнал запуска; временный каталог на ВМ будет удален автоматически.",
            evidence=read_error or f"exit={args.exit_code}",
        ))
    elif not findings:
        findings.append(finding(
            identifier="lynis_no_recommendations",
            title="Lynis не вернул warnings или suggestions",
            risk="info",
            status="passed",
            source="lynis",
            description="Временная проверка завершилась без нормализованных рекомендаций.",
            recommendation="Периодически повторяйте аудит после изменения роли сервера.",
        ))

    return base_report(
        args,
        "lynis",
        "lynis",
        findings,
        temporaryExecution=True,
        scannerExitCode=args.exit_code,
        hardeningIndex=hardening_index,
    )


def lynis_unavailable(args: argparse.Namespace) -> dict[str, Any]:
    return base_report(
        args,
        "lynis",
        "lynis",
        [finding(
            identifier="lynis_tool_missing",
            title="Lynis не установлен на управляющей машине",
            risk="info",
            status="manual",
            source="lynis",
            description="Временный запуск на ВМ не начинался; пакеты и файлы на управляемом хосте не изменялись.",
            recommendation="Установите lynis только на control node и повторите аудит.",
        )],
        available=False,
        temporaryExecution=False,
    )


def local_name(element: element_tree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def child_text(element: element_tree.Element, wanted_name: str) -> str:
    for child in element:
        if local_name(child) == wanted_name:
            return (child.text or "").strip()
    return ""


def risk_from_severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"critical", "high"}:
        return "high"
    if normalized in {"medium", "moderate"}:
        return "medium"
    if normalized in {"low"}:
        return "low"
    return "info"


def openscap_arf(args: argparse.Namespace) -> dict[str, Any]:
    try:
        root = element_tree.parse(args.input).getroot()
    except (OSError, element_tree.ParseError) as error:
        return base_report(
            args,
            "openscap",
            "openscap",
            [finding(
                identifier="openscap_arf_unreadable",
                title="OpenSCAP не сформировал читаемый ARF-отчёт",
                risk="info",
                status="manual",
                source="openscap",
                description="Соответствие SSG-профилю не подтверждено: результат OpenSCAP нельзя разобрать.",
                recommendation="Проверьте выбранные datastream и профиль, затем повторите аудит.",
                evidence=str(error),
            )],
            available=True,
            profile=args.profile,
            datastream=args.datastream,
            scannerExitCode=args.exit_code,
        )

    titles: dict[str, str] = {}
    severities: dict[str, str] = {}
    for element in root.iter():
        if local_name(element) != "Rule":
            continue
        identifier = element.get("id", "")
        if identifier:
            titles[identifier] = child_text(element, "title") or identifier
            severities[identifier] = element.get("severity", "")

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for element in root.iter():
        if local_name(element) != "rule-result":
            continue
        identifier = element.get("idref", "")
        result = child_text(element, "result").lower()
        if not identifier or identifier in seen or result in {"notapplicable", "notselected", "informational"}:
            continue
        seen.add(identifier)
        status = "passed" if result == "pass" else ("failed" if result == "fail" else "manual")
        severity = severities.get(identifier, "")
        findings.append(finding(
            identifier=f"openscap_{identifier}"[:160],
            title=titles.get(identifier, identifier),
            risk=risk_from_severity(severity) if status == "failed" else "info",
            status=status,
            source="openscap",
            description=(
                "Правило SSG не выполнено на момент проверки."
                if status == "failed"
                else "OpenSCAP подтвердил выполнение правила."
                if status == "passed"
                else "OpenSCAP не смог однозначно оценить правило; результат требует ручной проверки."
            ),
            recommendation=(
                "Откройте описание правила в SSG, оцените влияние на роль сервера и внесите изменение отдельным approval-playbook."
                if status != "passed"
                else "Повторяйте проверку после изменения ОС или базовой конфигурации."
            ),
            evidence=f"rule={identifier}; result={result or 'unknown'}; severity={severity or 'unknown'}",
        ))

    if not findings:
        findings.append(finding(
            identifier="openscap_no_rule_results",
            title="OpenSCAP не вернул оцениваемые правила",
            risk="info",
            status="manual",
            source="openscap",
            description="Пустой результат не означает соответствие: выбранный профиль или ARF нужно проверить вручную.",
            recommendation="Проверьте идентификатор профиля командой oscap info и повторите проверку.",
            evidence=f"exit={args.exit_code}",
        ))

    return base_report(
        args,
        "openscap",
        "openscap",
        findings[:800],
        available=True,
        profile=args.profile,
        datastream=args.datastream,
        scannerExitCode=args.exit_code,
    )


def openscap_unavailable(args: argparse.Namespace) -> dict[str, Any]:
    return base_report(
        args,
        "openscap",
        "openscap",
        [finding(
            identifier="openscap_prerequisite_missing",
            title="OpenSCAP-проверка не запускалась",
            risk="info",
            status="manual",
            source="openscap",
            description=args.reason or "На хосте или control node не выполнены условия для точной SCAP-проверки.",
            recommendation="Подготовьте oscap и SSG datastream на целевой ВМ, явно задайте HCP_OPENSCAP_DATASTREAM и HCP_OPENSCAP_PROFILE, затем повторите аудит.",
        )],
        available=False,
        reason=args.reason or None,
    )


def greenbone_report(args: argparse.Namespace) -> dict[str, Any]:
    try:
        root = element_tree.parse(args.input).getroot()
    except (OSError, element_tree.ParseError) as error:
        return base_report(
            args,
            "greenbone",
            "greenbone",
            [finding(
                identifier="greenbone_xml_unreadable",
                title="Не удалось прочитать XML-отчёт Greenbone",
                risk="info",
                status="manual",
                source="greenbone",
                description="Импорт не подтверждает отсутствие уязвимостей: файл не соответствует ожидаемому формату отчёта.",
                recommendation="Экспортируйте результат задачи Greenbone в XML и загрузите файл повторно.",
                evidence=str(error),
            )],
            imported=False,
        )

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for element in root.iter():
        if local_name(element) != "result":
            continue
        identifier = child_text(element, "id") or element.get("id", "")
        host = child_text(element, "host")
        port = child_text(element, "port")
        nvt = next((child for child in element if local_name(child) == "nvt"), None)
        oid = nvt.get("oid", "") if nvt is not None else ""
        name = child_text(nvt, "name") if nvt is not None else ""
        severity_text = child_text(element, "severity")
        threat = child_text(element, "threat")
        try:
            severity_score = float(severity_text)
        except ValueError:
            severity_score = 0.0
        normalized_threat = threat.lower()
        status = "failed"
        if normalized_threat in {"log", "false positive", "false_positive"}:
            status = "manual"
        risk = "high" if severity_score >= 7 else "medium" if severity_score >= 4 else "low" if severity_score > 0 else "info"
        key = (oid or identifier or name or "greenbone-result") + "-" + host + "-" + port
        if key in seen:
            continue
        seen.add(key)
        description = child_text(element, "description")
        solution = child_text(element, "solution")
        cves = child_text(nvt, "cve") if nvt is not None else ""
        findings.append(finding(
            identifier=("greenbone_" + key).replace(" ", "_")[:160],
            title=name or "Находка Greenbone/OpenVAS",
            risk=risk,
            status=status,
            source="greenbone",
            description=(description or "Greenbone сообщил о сетевой уязвимости.")[:1200],
            recommendation=(solution or "Проверьте рекомендации производителя и примените исправление по утверждённой процедуре.")[:1200],
            evidence=f"result={identifier}; oid={oid or 'unknown'}; host={host or 'unknown'}; port={port or 'unknown'}; threat={threat or 'unknown'}; severity={severity_text or 'unknown'}; cve={cves or 'none'}",
        ))

    if not findings:
        findings.append(finding(
            identifier="greenbone_no_results",
            title="В XML-отчёте Greenbone нет результатов",
            risk="info",
            status="manual",
            source="greenbone",
            description="Пустой импорт не подтверждает безопасность: проверьте статус задачи, цель и актуальность VT-feeds в Greenbone.",
            recommendation="Убедитесь, что задача завершена и экспортирован именно report XML.",
        ))

    return base_report(args, "greenbone", "greenbone", findings[:1000], imported=True, importedFrom="Greenbone XML")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("ssh-audit", "nmap", "lynis-report", "lynis-unavailable", "openscap-arf", "openscap-unavailable", "greenbone-report"))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--inventory-host", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--input")
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--profile")
    parser.add_argument("--datastream")
    parser.add_argument("--reason")
    args = parser.parse_args()
    if args.mode in {"ssh-audit", "nmap"} and not args.host:
        parser.error("--host is required for network scanner modes")
    if args.mode in {"lynis-report", "openscap-arf", "greenbone-report"} and not args.input:
        parser.error(f"--input is required for {args.mode}")
    return args


def main() -> int:
    args = parse_args()
    report = {
        "ssh-audit": ssh_audit,
        "nmap": nmap,
        "lynis-report": lynis_report,
        "lynis-unavailable": lynis_unavailable,
        "openscap-arf": openscap_arf,
        "openscap-unavailable": openscap_unavailable,
        "greenbone-report": greenbone_report,
    }[args.mode](args)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(destination)
    return 0


if __name__ == "__main__":
    sys.exit(main())
