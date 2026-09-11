#!/usr/bin/env python3
"""Read-only standalone OVAL evaluation for the Astra family, Python 3.5+.

The administrator declares a source scope; this is not vendor certification.
Only OpenSCAP evaluates package/version predicates. The adapter never derives
CVE status by comparing version strings or maps Astra to Debian advisories.
"""
from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

DEFINITIONS_NS = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
RESULTS_NS = 'http://oval.mitre.org/XMLSchema/oval-results-5'
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_RESULT_BYTES = 128 * 1024 * 1024
MAX_XML_NODES = 600000
MAX_DEFINITIONS = 30000
UTC = datetime.timezone.utc
# Local, read-only probes only. SQL objects could open network connections.
LOCAL_OBJECTS = frozenset(('dpkginfo', 'rpminfo', 'family', 'uname', 'textfilecontent',
    'textfilecontent54', 'file', 'fileextendedattribute', 'filehash', 'filehash58',
    'system_info', 'variable', 'environmentvariable', 'environmentvariable58',
    'sysctl', 'process', 'process58', 'partition', 'systemdunitproperty',
    'systemdunitdependency', 'inetlisteningservers', 'iflisteners', 'interface',
    'routingtable', 'runlevel', 'symlink', 'selinuxboolean', 'selinuxsecuritycontext',
    'rpmverify', 'rpmverifyfile', 'rpmverifypackage', 'password', 'shadow', 'xinetd'))


def now():
    return datetime.datetime.now(UTC)


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def node_text(node):
    return ''.join(node.itertext()).strip() if node is not None else ''


def child(node, name):
    return next((item for item in node if local_name(item.tag) == name), None)


def parse_config(raw):
    value = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(value, dict):
        raise ValueError('Конфигурация OVAL должна быть объектом JSON.')
    config = dict(value)
    config.setdefault('mode', 'local')
    config.setdefault('path', '/usr/share/oval/db.xml')
    config.setdefault('url', '')
    config.setdefault('sha256', '')
    config.setdefault('releasePattern', '')
    config.setdefault('architectures', [])
    config.setdefault('maxAgeDays', 30)
    if config['mode'] not in ('local', 'online'):
        raise ValueError('Источник OVAL должен быть local или online.')
    for name in ('path', 'url', 'sha256', 'releasePattern'):
        if not isinstance(config[name], str):
            raise ValueError('Поле ' + name + ' должно быть строкой.')
    config['sha256'] = config['sha256'].lower()
    if config['sha256'] and not re.match(r'^[a-f0-9]{64}$', config['sha256']):
        raise ValueError('Ожидаемый SHA-256 должен содержать 64 шестнадцатеричных символа.')
    if not re.match(r'^(?:\*|[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}(?:\.\*)?)$', config['releasePattern']):
        raise ValueError('Укажите область выпуска: *, точный выпуск или префикс с .* .')
    if (not isinstance(config['architectures'], list)
            or len(config['architectures']) > 16
            or any(not isinstance(x, str) or not re.match(r'^[A-Za-z0-9_-]{1,32}$', x)
                   for x in config['architectures'])):
        raise ValueError('Некорректный список архитектур OVAL.')
    if type(config['maxAgeDays']) is not int or not 1 <= config['maxAgeDays'] <= 3650:
        raise ValueError('Срок актуальности должен быть от 1 до 3650 дней.')
    if config['mode'] == 'online':
        https_origin(config['url'])
        if not config['sha256']:
            raise ValueError('Для загрузки OVAL обязателен ожидаемый SHA-256 из доверенного источника.')
    elif (not os.path.isabs(config['path']) or len(config['path']) > 1024
          or any(ord(c) < 32 or ord(c) == 127 for c in config['path'])
          or '..' in config['path'].split('/')):
        raise ValueError('Локальный OVAL требует абсолютный путь без .. .')
    return config


def https_origin(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.query or len(url) > 2048
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url)):
        raise ValueError('Источник должен быть HTTPS URL без логина, пароля и фрагмента.')
    try:
        port = parsed.port or 443
    except ValueError:
        raise ValueError('Некорректный порт HTTPS источника.')
    return parsed.hostname.lower(), port


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if https_origin(newurl) != self.origin:
            raise ValueError('Перенаправление OVAL за пределы выбранного HTTPS источника запрещено.')
        return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


def read_regular(path, limit):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('OVAL должен быть обычным файлом в пределах лимита размера.')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if len(raw) > limit:
            raise ValueError('Превышен предел размера OVAL.')
        if ((before.st_ino, before.st_size, before.st_mtime, before.st_ctime)
                != (after.st_ino, after.st_size, after.st_mtime, after.st_ctime)
                or len(raw) != before.st_size):
            raise ValueError('OVAL изменился во время чтения.')
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def safe_xml(raw):
    # Reject alternate encodings so declaration scanning cannot be bypassed
    # with UTF-16/32. No DTD, entities or XInclude are needed by standalone OVAL.
    if b'\x00' in raw or re.search(br'<!\s*(?:DOCTYPE|ENTITY)', raw, re.I):
        raise ValueError('DTD, сущности и кодировки с NUL не разрешены для OVAL.')
    declaration = re.search(br'<\?xml[^>]*encoding\s*=\s*[\"\']([^\"\']+)', raw[:250], re.I)
    if declaration and declaration.group(1).lower() not in (b'utf-8', b'utf8', b'us-ascii'):
        raise ValueError('Для OVAL поддерживается XML UTF-8.')
    root = ET.fromstring(raw)
    count = 0
    pending = [(root, 0)]
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_XML_NODES or depth > 100:
            raise ValueError('Превышена допустимая сложность XML OVAL.')
        if node.tag.startswith('{http://www.w3.org/2001/XInclude}'):
            raise ValueError('Внешние XML включения запрещены.')
        pending.extend((item, depth + 1) for item in node)
    return root


def source_definitions(root):
    if root.tag != '{' + DEFINITIONS_NS + '}oval_definitions':
        raise ValueError('Ожидается самостоятельный файл oval_definitions; XCCDF и datastream проверяются отдельно.')
    for node in root.iter():
        name = local_name(node.tag)
        if name == 'external_variable':
            raise ValueError('База требует внешние OVAL переменные; самостоятельная проверка без них неполна.')
        if name.endswith('_object') and name[:-7] not in LOCAL_OBJECTS:
            raise ValueError('Объект OVAL не входит в локальные read-only проверки: ' + name)
    definitions = child(root, 'definitions')
    result = {}
    if definitions is not None:
        for node in definitions:
            identifier = node.get('id', '')
            if not identifier or identifier in result:
                raise ValueError('Пустой или повторяющийся идентификатор определения OVAL.')
            result[identifier] = node
    if not result or len(result) > MAX_DEFINITIONS:
        raise ValueError('База не содержит определений либо превышает лимит 30000 определений.')
    return result


def parse_timestamp(value):
    match = re.match(r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$', value)
    if not match:
        raise ValueError('Дата генерации OVAL отсутствует или имеет неизвестный формат.')
    result = datetime.datetime.strptime(match.group(1) + 'T' + match.group(2), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=UTC)
    zone = match.group(3)
    if zone and zone != 'Z':
        hours, minutes = map(int, zone[1:].split(':'))
        if hours > 23 or minutes > 59:
            raise ValueError('Некорректный часовой пояс OVAL.')
        offset = datetime.timedelta(hours=hours, minutes=minutes)
        result = result - offset if zone[0] == '+' else result + offset
    return result


def source_metadata(root, raw, config, current_time=None):
    current_time = current_time or now()
    generator = child(root, 'generator')
    values = dict((local_name(n.tag), node_text(n)) for n in generator) if generator is not None else {}
    digest = hashlib.sha256(raw).hexdigest()
    if config['sha256'] and digest != config['sha256']:
        raise ValueError('SHA-256 OVAL не совпадает с ожидаемым: выполнение остановлено.')
    reasons = []
    for node in root.iter():
        if local_name(node.tag) == 'dpkginfo_state' and any(local_name(n.tag) == 'evr' and n.get('datatype') == 'evr_string' for n in node):
            reasons.append('OVAL использует evr_string для DPKG: стандарт рекомендует debian_evr_string; точность сравнения версий требует проверки источника.')
            break
    if not config['sha256']:
        reasons.append('Ожидаемый SHA-256 не задан: целостность относительно доверенной копии не подтверждена.')
    timestamp = values.get('timestamp', '')
    age_days = None
    freshness = 'unknown'
    try:
        age_seconds = (current_time - parse_timestamp(timestamp)).total_seconds()
        age_days = round(age_seconds / 86400.0, 3)
        if age_seconds < -300:
            freshness = 'future'
            reasons.append('Дата генерации OVAL находится в будущем; проверьте часы и источник.')
        elif age_seconds > config['maxAgeDays'] * 86400:
            freshness = 'stale'
            reasons.append('Возраст базы OVAL превышает выбранный срок актуальности.')
        else:
            freshness = 'current'
    except ValueError as error:
        reasons.append(str(error))
    return {
        'sourceMode': config['mode'], 'path': config['path'] if config['mode'] == 'local' else None,
        'url': config['url'] if config['mode'] == 'online' else None,
        'sha256': digest, 'expectedSha256': config['sha256'] or None,
        'checksumVerified': bool(config['sha256']), 'bytes': len(raw),
        'generatedAt': timestamp or None, 'ageDays': age_days, 'freshness': freshness,
        'maxAgeDays': config['maxAgeDays'], 'generator': values,
        'vendorSignature': 'not_checked', 'scopeAuthority': 'administrator_declared',
        'releasePattern': config['releasePattern'], 'architectures': config['architectures'],
        'vendorReleaseApplicability': 'not_verified',
    }, reasons


def host_identity():
    release = ''
    values = {}
    try:
        release = read_regular('/etc/astra_version', 4096).decode('utf-8').strip()
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        for line in read_regular('/etc/os-release', 65536).decode('utf-8').splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                values[key] = value.strip().strip('"\'')
    except (OSError, ValueError, UnicodeError):
        # /etc/os-release is commonly a symlink; use its standard vendor target.
        try:
            for line in read_regular('/usr/lib/os-release', 65536).decode('utf-8').splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    values[key] = value.strip().strip('"\'')
        except (OSError, ValueError, UnicodeError):
            pass
    architecture = os.uname().machine
    return {'id': values.get('ID', ''), 'astraVersion': release,
            'architecture': architecture, 'prettyName': values.get('PRETTY_NAME', '')}


def check_scope(identity, config):
    if identity.get('id') != 'astra' or not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}$', identity.get('astraVersion', '')):
        raise ValueError('Не подтверждены семейство Astra и выпуск из /etc/astra_version.')
    pattern = config['releasePattern']
    actual = identity['astraVersion']
    matches = pattern == '*' or actual == pattern or (pattern.endswith('.*') and
        (actual == pattern[:-2] or actual.startswith(pattern[:-1])))
    if not matches:
        raise ValueError('Выпуск Astra ' + actual + ' не входит в область выбранной базы ' + pattern + '.')
    aliases = {'amd64': 'x86_64', 'arm64': 'aarch64', 'i386': 'x86', 'i686': 'x86'}
    arch = aliases.get(identity['architecture'], identity['architecture'])
    if config['architectures'] and arch not in [aliases.get(x, x) for x in config['architectures']]:
        raise ValueError('Архитектура хоста не входит в область выбранной базы OVAL.')


def prepare(config, output):
    if config['mode'] != 'online':
        raise ValueError('Подготовка загрузки используется только для online источника.')
    origin = https_origin(config['url'])
    opener = urllib.request.build_opener(SameOriginRedirect(origin))
    request = urllib.request.Request(config['url'], headers={'User-Agent': 'HCP-OVAL/1', 'Accept': 'application/xml'})
    chunks, size = [], 0
    started = time.monotonic()
    with opener.open(request, timeout=30) as response:
        if https_origin(response.geturl()) != origin:
            raise ValueError('HTTPS источник изменился при загрузке OVAL.')
        if response.headers.get('Content-Encoding', 'identity') not in ('identity', ''):
            raise ValueError('Сжатая передача OVAL не поддерживается; выберите прямой XML.')
        while True:
            piece = response.read1(65536)
            if not piece:
                break
            size += len(piece)
            if size > MAX_SOURCE_BYTES or time.monotonic() - started > 120:
                raise ValueError('Превышен лимит размера или времени загрузки OVAL.')
            chunks.append(piece)
    raw = b''.join(chunks)
    root = safe_xml(raw)
    source_definitions(root)
    metadata, reasons = source_metadata(root, raw, config)
    write_bytes(output, raw)
    return {'ok': True, 'path': output, 'database': metadata, 'warnings': reasons}


def write_bytes(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)


def run_oscap(command, directory, timeout=900, capture_stdout=False):
    # Bound logs and result files as well as run time; kill the entire probe
    # process group on timeout. No shell, package installation or fetch option.
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT_BYTES, MAX_RESULT_BYTES))
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, cwd=directory, stdout=stdout, stderr=stderr,
                                   start_new_session=True, preexec_fn=limits)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return None, 'Превышено время OpenSCAP (' + str(timeout) + ' с).'
        stderr.seek(0)
        detail = stderr.read(8192).decode('utf-8', 'replace')
        if capture_stdout:
            stdout.seek(0)
            detail = stdout.read(8192).decode('utf-8', 'replace') + detail
        return code, detail


def xml_evidence(node):
    if node is None:
        return None
    return {'type': local_name(node.tag), 'attributes': dict(node.attrib),
            'text': (node.text or '').strip(), 'children': [xml_evidence(n) for n in node]}


def definition_metadata(node):
    metadata = child(node, 'metadata')
    references = []
    cves = set()
    if metadata is not None:
        for reference in metadata.iter():
            if local_name(reference.tag) == 'reference':
                references.append(dict(reference.attrib))
                identifier = reference.get('ref_id', '').upper()
                if re.match(r'^CVE-\d{4}-\d{4,}$', identifier):
                    cves.add(identifier)
    severity = next((node_text(n) for n in metadata.iter() if local_name(n.tag) == 'severity'), '') if metadata is not None else ''
    return {'id': node.get('id'), 'version': node.get('version'), 'class': node.get('class', ''),
            'title': node_text(child(metadata, 'title')) if metadata is not None else '',
            'description': node_text(child(metadata, 'description')) if metadata is not None else '',
            'references': references, 'cveIds': sorted(cves), 'vendorSeverity': severity or None,
            'criteria': xml_evidence(child(node, 'criteria'))}


def finding(identifier, title, status, description, evidence='', risk='info'):
    return {'id': identifier, 'profileId': 'astra-oval', 'title': title,
            'category': 'Уязвимости пакетов Astra', 'risk': risk, 'status': status,
            'source': 'openscap', 'description': description,
            'recommendation': 'Проверьте бюллетень производителя и применимость обновления; после обновления повторите аудит.',
            'remediationAvailable': False, 'remediationId': None, 'affectedFiles': [],
            'evidence': evidence[:3000], 'evidenceTruncated': len(evidence) > 3000}


def empty_report(args, reason=None):
    report = {'schemaVersion': 1, 'action': 'astraOvalAudit', 'runId': args.run_id,
              'inventoryHost': args.inventory_host, 'hostname': args.inventory_host,
              'createdAt': now().isoformat(), 'os': None, 'profileId': 'astra-oval', 'mode': 'astra-oval',
              'scanner': {'source': 'openscap', 'available': False, 'partial': True,
                  'fullCveCoverage': False, 'evaluationPerformed': False, 'uniqueCveCount': None,
                  'definitionResults': [], 'partialReasons': []},
              'summary': {'score': None, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
              'findings': [], 'events': []}
    if reason:
        report['scanner']['partialReasons'].append(reason)
    return report


def finish(report):
    scanner = report['scanner']
    scanner['partialReasons'] = list(dict.fromkeys(scanner['partialReasons']))
    scanner['partial'] = bool(scanner['partialReasons']) or not scanner['evaluationPerformed']
    if scanner['partial']:
        report['findings'].append(finding('astra_oval_incomplete', 'CVE-аудит Astra выполнен не полностью', 'manual',
            'Отсутствие находок не означает отсутствие уязвимостей.', '\n'.join(scanner['partialReasons'])))
    if scanner['evaluationPerformed']:
        report['findings'].append(finding('astra_oval_scope', 'Область оценки: выбранная база OVAL', 'manual',
            'Результаты относятся к определениям выбранной базы. Полнота охвата всех CVE и подпись производителя не подтверждены.',
            'Уникальных CVE по истинным vulnerability-определениям: ' + (str(scanner['uniqueCveCount']) if scanner['uniqueCveCount'] is not None else 'оценка недоступна')
            + '; область выпуска заявлена администратором.'))
    findings = report['findings']
    report['summary'] = {'score': None, 'total': len(findings),
        'high': sum(f['risk'] == 'high' and f['status'] == 'failed' for f in findings),
        'medium': sum(f['risk'] == 'medium' and f['status'] == 'failed' for f in findings),
        'low': sum(f['risk'] == 'low' and f['status'] == 'failed' for f in findings),
        'info': sum(f['risk'] == 'info' for f in findings)}
    return report


def parse_results(root, definitions, report):
    if root.tag != '{' + RESULTS_NS + '}oval_results':
        raise ValueError('OpenSCAP не вернул документ oval_results.')
    results = root.find('{' + RESULTS_NS + '}results')
    systems = list(results) if results is not None else []
    if len(systems) != 1 or local_name(systems[0].tag) != 'system':
        raise ValueError('Ожидается результат OVAL ровно для одной локальной системы.')
    system = systems[0]
    nodes = child(system, 'definitions')
    mapped = {}
    if nodes is not None:
        for node in nodes:
            identifier = node.get('definition_id', '')
            if identifier not in definitions or identifier in mapped:
                raise ValueError('Неизвестный или повторяющийся результат определения OVAL.')
            if node.get('variable_instance', '1') != '1':
                raise ValueError('Множественные экземпляры внешних переменных не поддерживаются.')
            mapped[identifier] = node
    scanner = report['scanner']
    counts, positive_cves = {}, set()
    vulnerability_count = 0
    evaluated_vulnerability_count = 0
    for identifier, source in sorted(definitions.items()):
        entry = definition_metadata(source)
        result = mapped.get(identifier)
        status = result.get('result', '') if result is not None else 'missing'
        entry['result'] = status
        if entry['class'] == 'vulnerability':
            vulnerability_count += 1
            if status in ('true', 'false'):
                evaluated_vulnerability_count += 1
        entry['resultCriteria'] = xml_evidence(child(result, 'criteria')) if result is not None else None
        scanner['definitionResults'].append(entry)
        counts[status] = counts.get(status, 0) + 1
        if status not in ('true', 'false', 'not applicable'):
            scanner['partialReasons'].append('Не завершено определение ' + identifier + ': ' + status)
        if status == 'true' and entry['class'] == 'vulnerability':
            positive_cves.update(entry['cveIds'])
            severity = (entry['vendorSeverity'] or '').lower()
            risk = {'critical': 'high', 'high': 'high', 'important': 'high', 'medium': 'medium',
                    'moderate': 'medium', 'low': 'low'}.get(severity, 'info')
            item = finding(identifier, (', '.join(entry['cveIds']) + ': ' if entry['cveIds'] else '') + (entry['title'] or identifier),
                'failed', entry['description'] or 'OpenSCAP подтвердил условия vulnerability-определения OVAL.',
                json.dumps({'definitionId': identifier, 'cveIds': entry['cveIds'], 'result': status,
                            'vendorSeverity': entry['vendorSeverity'], 'criteria': entry['resultCriteria']}, ensure_ascii=False), risk)
            item['vulnerability'] = {'cveIds': entry['cveIds'], 'definitionId': identifier,
                'severitySource': 'oval_metadata' if severity else 'not_provided', 'cvss': None}
            report['findings'].append(item)
        elif status == 'true' and entry['class'] not in ('vulnerability', 'inventory'):
            report['findings'].append(finding(identifier, 'OVAL ' + entry['class'] + ': ' + (entry['title'] or identifier),
                'manual', 'Истинное определение этого класса не преобразуется автоматически в найденную CVE.',
                json.dumps({'class': entry['class'], 'references': entry['references'], 'result': status}, ensure_ascii=False)))
    scanner['resultCounts'] = counts
    scanner['definitionCount'] = len(definitions)
    scanner['vulnerabilityDefinitionCount'] = vulnerability_count
    scanner['evaluatedVulnerabilityDefinitionCount'] = evaluated_vulnerability_count
    if not vulnerability_count:
        scanner['partialReasons'].append('База не содержит vulnerability-определений: CVE-аудит не выполнен.')
    elif not evaluated_vulnerability_count:
        scanner['partialReasons'].append('Ни одно vulnerability-определение не получило true/false; применимая CVE-оценка отсутствует.')
    scanner['uniqueCveCount'] = len(positive_cves) if evaluated_vulnerability_count else None
    scanner['cveIds'] = sorted(positive_cves)
    scanner['evaluatedDefinitionCount'] = len(mapped)
    # Preserve package evidence and result references, excluding arbitrary
    # collected file contents, environment values, passwords and shadow data.
    scanner['testResults'] = []
    tests = child(system, 'tests')
    if tests is not None:
        for test in tests:
            scanner['testResults'].append({'attributes': dict(test.attrib),
                'testedItems': [dict(n.attrib) for n in test if local_name(n.tag) == 'tested_item']})
    scanner['packageItems'] = []
    for node in system.iter():
        if local_name(node.tag) in ('dpkginfo_item', 'rpminfo_item'):
            allowed = ('name', 'epoch', 'version', 'release', 'arch', 'evr', 'extended_name')
            scanner['packageItems'].append({'attributes': dict(node.attrib),
                'type': local_name(node.tag), 'values': dict((local_name(n.tag), node_text(n)) for n in node if local_name(n.tag) in allowed)})
    scanner['evaluationPerformed'] = True


def evaluate(args):
    report = empty_report(args)
    scanner = report['scanner']
    try:
        config = parse_config(args.config)
        identity = host_identity()
        scanner['hostIdentity'] = identity
        report['os'] = identity.get('prettyName') or None
        check_scope(identity, config)
        path = args.input or config['path']
        if config['mode'] == 'online' and not args.input:
            raise ValueError('Online база должна быть предварительно загружена управляющим узлом.')
        raw = read_regular(path, MAX_SOURCE_BYTES)
        root = safe_xml(raw)
        definitions = source_definitions(root)
        scanner['database'], warnings = source_metadata(root, raw, config)
        scanner['definitionTests'] = [xml_evidence(n) for n in (child(root, 'tests') or [])]
        scanner['packagePredicates'] = [xml_evidence(n) for n in root.iter()
            if local_name(n.tag) in ('dpkginfo_object', 'dpkginfo_state', 'rpminfo_object', 'rpminfo_state')]
        scanner['partialReasons'].extend(warnings)
        binary = shutil.which('oscap')
        scanner['available'] = bool(binary)
        if not binary:
            raise ValueError('OpenSCAP (oscap) не установлен на целевом хосте.')
        with tempfile.TemporaryDirectory(prefix='hcp-oval-') as directory:
            source_path = os.path.join(directory, 'definitions.xml')
            result_path = os.path.join(directory, 'results.xml')
            write_bytes(source_path, raw)
            version_code, version_text = run_oscap([binary, '--version'], directory, 10, capture_stdout=True)
            scanner['version'] = version_text.splitlines()[0][:300] if version_code == 0 and version_text else None
            code, detail = run_oscap([binary, 'oval', 'validate', source_path], directory, 120)
            scanner['validationExitCode'] = code
            if code != 0:
                raise ValueError('Проверка формата OVAL не пройдена: ' + detail)
            code, detail = run_oscap([binary, 'oval', 'eval', '--results', result_path, source_path], directory)
            scanner['exitCode'] = code
            if code not in (0, 2):
                scanner['partialReasons'].append('OpenSCAP завершился с ошибкой: ' + str(code) + '; ' + detail)
            result_raw = read_regular(result_path, MAX_RESULT_BYTES)
            scanner['resultSha256'] = hashlib.sha256(result_raw).hexdigest()
            parse_results(safe_xml(result_raw), definitions, report)
    except (OSError, ValueError, ET.ParseError, UnicodeError, subprocess.SubprocessError) as error:
        scanner['partialReasons'].append(str(error))
    return finish(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'evaluate', 'unavailable'))
    parser.add_argument('--config', default='{}')
    parser.add_argument('--input', default='')
    parser.add_argument('--output', required=True)
    parser.add_argument('--inventory-host', default='localhost')
    parser.add_argument('--run-id', default='manual')
    parser.add_argument('--reason', default='Источник OVAL недоступен.')
    args = parser.parse_args()
    if args.command == 'prepare':
        try:
            result = prepare(parse_config(args.config), args.output)
        except (OSError, ValueError, ET.ParseError, UnicodeError) as error:
            result = {'ok': False, 'error': str(error)}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    report = evaluate(args) if args.command == 'evaluate' else finish(empty_report(args, args.reason))
    # Existing report IDs should be unique; no silent overwrite or symlink follow.
    write_bytes(args.output, (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
