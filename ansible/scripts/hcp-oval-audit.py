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
import html
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
# The official Astra 1.7 feed on 2026-10-06 has 131721258 bytes and
# 796021 XML nodes. Keep bounded headroom for it and OpenSCAP results.
MAX_SOURCE_BYTES = 192 * 1024 * 1024
MAX_RESULT_BYTES = 384 * 1024 * 1024
MAX_XML_NODES = 2400000
MAX_DEFINITIONS = 30000
DOWNLOAD_TIMEOUT = 900
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
    config.setdefault('sourceName', '')
    config.setdefault('sourceReference', '')
    config.setdefault('sourceReviewedAt', None)
    if config['mode'] not in ('local', 'online'):
        raise ValueError('Источник OVAL должен быть local или online.')
    for name in ('path', 'url', 'sha256', 'releasePattern', 'sourceName', 'sourceReference'):
        if not isinstance(config[name], str):
            raise ValueError('Поле ' + name + ' должно быть строкой.')
    if config['sourceReviewedAt'] is not None and not isinstance(config['sourceReviewedAt'], str):
        raise ValueError('Поле sourceReviewedAt должно быть строкой или null.')
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
    if (len(config['sourceName']) > 160 or len(config['sourceReference']) > 500
            or any(ord(c) < 32 or ord(c) == 127 for c in config['sourceName'] + config['sourceReference'])):
        raise ValueError('Реквизиты доверенного источника OVAL содержат недопустимые символы.')
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


def indexed_schematron(raw):
    """Keep every installed Schematron rule; index references and dispatch.

    OpenSCAP's generated XSLT walks the whole XML once per rule group and
    searches every object/state for each reference. On large vendor feeds this
    is quadratic. XSLT keys preserve the same lookup node sets; dispatching to
    the union of *all* rule matches preserves normal template priority and
    document order, without hundreds of full recursive walks.

    Only the recognized generated format is optimized. Unknown stylesheets
    remain untouched and use ordinary OpenSCAP validation.
    """
    source = raw.decode('utf-8')
    if ('<axsl:stylesheet ' not in source or
            'xmlns:oval-def="' + DEFINITIONS_NS + '"' not in source or
            '<axsl:param ' not in source or 'hcp-index-' in source):
        return None
    rewritten = 0
    for section in ('objects', 'states', 'variables'):
        key = 'hcp-index-' + section
        source, count = re.subn(
            r'ancestor::oval-def:oval_definitions/oval-def:' + section + r'/\*\[@id=(\$\w+|current\(\))\]',
            lambda match: "key('" + key + "', " + match.group(1) + ")", source)
        rewritten += count
        if section != 'variables':
            attribute = 'object_ref' if section == 'objects' else 'state_ref'
            source, count = re.subn(
                r'@' + attribute + r'=ancestor::oval-def:oval_definitions/oval-def:' + section + r'/([\w-]+:[\w-]+)/@id',
                lambda match: "key('" + key + "', @" + attribute + ")[self::" + match.group(1) + "]", source)
            rewritten += count
        declaration = '<axsl:key name="' + key + '" match="oval-def:oval_definitions/oval-def:' + section + '/*" use="@id"/>'
        source = source.replace('<axsl:param ', declaration + '<axsl:param ', 1)

    namespace = '{http://www.w3.org/1999/XSL/Transform}'
    root = ET.fromstring(source)
    if root.tag != namespace + 'stylesheet':
        return None
    modes = {}
    rules = 0
    for template in root.findall(namespace + 'template'):
        mode = template.get('mode', '')
        if not re.match(r'^M[0-9]+$', mode):
            continue
        priority = float(template.get('priority', '0'))
        if priority >= 1000:
            match = template.get('match', '')
            # Union separators inside literals/predicates are not supported.
            # Fall back rather than guess about a new compiler's match grammar.
            parts = match.split('|')
            if any(not re.match(r'^[A-Za-z_@*]', part.strip()) or
                   part.count("'") % 2 or part.count('"') % 2 or
                   part.count('[') != part.count(']') or '$' in part or
                   'key(' in part or 'id(' in part or 'current(' in part for part in parts):
                return None
            modes.setdefault(mode, []).extend(parts)
            rules += 1
        elif priority < 0:
            if any(child.tag != namespace + 'apply-templates' or
                   child.get('select') != '@*|*' or child.get('mode') != mode for child in template):
                return None
        else:
            return None
    if not modes:
        return None
    for mode, matches in modes.items():
        original = '<axsl:apply-templates select="/" mode="' + mode + '"/>'
        if source.count(original) != 1:
            return None
        select = ' | '.join('//' + match.strip() for match in matches)
        source = source.replace(original, '<axsl:apply-templates select="' + html.escape(select, quote=True) + '" mode="' + mode + '"/>')
        source = source.replace('<axsl:apply-templates select="@*|*" mode="' + mode + '"/>', '')
    optimized = source.encode('utf-8')
    return optimized, {'method': 'indexed-references-and-rule-dispatch',
        'originalSha256': hashlib.sha256(raw).hexdigest(),
        'optimizedSha256': hashlib.sha256(optimized).hexdigest(),
        'indexedLookups': rewritten, 'ruleGroups': len(modes),
        'rules': rules}


def schematron_environment(path, directory):
    """Use a private schema copy for this controller process only."""
    version = None
    with open(path, 'rb') as stream:
        for event, node in ET.iterparse(stream, events=('end',)):
            if local_name(node.tag) == 'schema_version' and not node.get('platform'):
                version = node_text(node)
                break
    if not version or not re.match(r'^\d+\.\d+(?:\.\d+)?$', version):
        return None, None
    base = os.environ.get('OSCAP_SCHEMA_PATH', '/usr/share/openscap/schemas')
    original = os.path.join(base, 'oval', version)
    stylesheet = os.path.join(original, 'oval-definitions-schematron.xsl')
    if not os.path.isfile(stylesheet):
        return None, None
    result = indexed_schematron(read_regular(stylesheet, 4 * 1024 * 1024))
    if result is None:
        return None, None
    optimized, evidence = result
    private = os.path.join(directory, 'schemas')
    target = os.path.join(private, 'oval', version)
    shutil.copytree(original, target)
    shutil.copytree(os.path.join(base, 'common'), os.path.join(private, 'common'))
    with open(os.path.join(target, 'oval-definitions-schematron.xsl'), 'wb') as stream:
        stream.write(optimized)
    environment = dict(os.environ, OSCAP_SCHEMA_PATH=private)
    return environment, evidence


def validate_for_transfer(binary, path, digest, size, directory):
    """Validate online bytes on the controller before the old target imports them.

    XSD is mandatory. A bounded optional Schematron pass can time out on a
    large feed; that remains an explicit partial-audit reason on the target.
    Any actual validation error stops evaluation. No XML rules are rewritten.
    """
    code, detail = run_oscap([binary, 'oval', 'validate', '--skip-schematron', path], directory, 120, capture_stdout=True)
    if code != 0:
        raise ValueError('Проверка XML OVAL по XSD на control node не пройдена: ' + detail)
    with tempfile.TemporaryDirectory(prefix='hcp-oval-validation-', dir=directory) as temporary:
        # Unit callers may substitute the XSD runner without a source file.
        environment, optimization = schematron_environment(path, temporary) if os.path.isfile(path) else (None, None)
        options = {'environment': environment} if environment is not None else {}
        code, detail = run_oscap([binary, 'oval', 'validate', path], directory,
                                120 if size > 64 * 1024 * 1024 else 600, capture_stdout=True, **options)
    if code not in (0, None):
        raise ValueError('Проверка Schematron OVAL на control node не пройдена: ' + detail)
    version_code, version = run_oscap([binary, '--version'], directory, 10, capture_stdout=True)
    return {'sha256': digest, 'schemaExitCode': 0, 'schematronExitCode': code,
            'schematronOptimization': optimization,
            'validator': version.splitlines()[0][:300] if version_code == 0 and version else 'OpenSCAP',
            'location': 'control_node'}


def use_controller_validation(args, config, digest, scanner):
    raw = getattr(args, 'source_validation', '{}')
    proof = json.loads(raw)
    if proof == {}:
        return False
    if (not isinstance(proof, dict) or config['mode'] != 'online' or not args.input
            or proof.get('sha256') != digest or digest != config['sha256']
            or type(proof.get('schemaExitCode')) is not int or proof['schemaExitCode'] != 0
            or proof.get('schematronExitCode', 'missing') not in (0, None)
            or (proof.get('schematronExitCode') is not None and type(proof.get('schematronExitCode')) is not int)
            or proof.get('location') != 'control_node'
            or not isinstance(proof.get('validator'), str) or len(proof['validator']) > 300):
        raise ValueError('Результат проверки control node не относится к этим байтам OVAL.')
    scanner['sourceValidation'] = proof
    scanner['schemaValidationExitCode'] = 0
    scanner['validationExitCode'] = proof['schematronExitCode']
    if proof['schematronExitCode'] is None:
        scanner['partialReasons'].append('XML базы проверен по XSD на control node. Дополнительная проверка Schematron не завершилась за отведённое время; результат CVE-аудита считается частичным.')
    return True


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
    if not config['sourceName'] or not config['sourceReference']:
        reasons.append('Не зафиксированы название и реквизит доверенного источника OVAL: происхождение базы не подтверждено.')
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
        'sourceName': config['sourceName'] or None,
        'sourceReference': config['sourceReference'] or None,
        'sourceReviewedAt': config['sourceReviewedAt'],
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


def prepare(config, output, validate=False):
    if config['mode'] != 'online':
        raise ValueError('Подготовка загрузки используется только для online источника.')
    origin = https_origin(config['url'])
    opener = urllib.request.build_opener(SameOriginRedirect(origin))
    chunks, size = [], 0
    expected_size, etag = None, None
    started = time.monotonic()
    for attempt in range(3):
        if time.monotonic() - started > DOWNLOAD_TIMEOUT:
            raise ValueError('Превышено время загрузки OVAL (' + str(DOWNLOAD_TIMEOUT) + ' секунд).')
        headers = {'User-Agent': 'HCP-OVAL/1', 'Accept': 'application/xml'}
        if size:
            headers['Range'] = 'bytes=' + str(size) + '-'
            if etag:
                headers['If-Range'] = etag
        request = urllib.request.Request(config['url'], headers=headers)
        try:
            with opener.open(request, timeout=30) as response:
                if https_origin(response.geturl()) != origin:
                    raise ValueError('HTTPS источник изменился при загрузке OVAL.')
                if response.headers.get('Content-Encoding', 'identity') not in ('identity', ''):
                    raise ValueError('Сжатая передача OVAL не поддерживается; выберите прямой XML.')
                if size and response.getcode() == 206:
                    interval = re.match(r'^bytes (\d+)-(\d+)/(\d+)$', response.headers.get('Content-Range', ''))
                    if (not interval or int(interval.group(1)) != size or int(interval.group(2)) + 1 != int(interval.group(3))
                            or (expected_size is not None and int(interval.group(3)) != expected_size)
                            or (etag and response.headers.get('ETag') != etag)):
                        raise ValueError('Источник OVAL изменился или вернул неверный диапазон при продолжении загрузки.')
                    expected_size = int(interval.group(3))
                elif response.getcode() == 200:
                    # A server may ignore Range: restart, never append a full file.
                    chunks, size = [], 0
                    length = response.headers.get('Content-Length', '')
                    expected_size = int(length) if length.isdigit() else None
                    etag = response.headers.get('ETag')
                else:
                    raise ValueError('Источник вернул неожиданный HTTP-статус при загрузке OVAL.')
                if expected_size is not None and expected_size > MAX_SOURCE_BYTES:
                    raise ValueError('База OVAL превышает допустимый размер 192 МиБ.')
                while True:
                    piece = response.read1(65536)
                    if not piece:
                        break
                    size += len(piece)
                    if size > MAX_SOURCE_BYTES:
                        raise ValueError('База OVAL превышает допустимый размер 192 МиБ.')
                    if time.monotonic() - started > DOWNLOAD_TIMEOUT:
                        raise ValueError('Превышено время загрузки OVAL (' + str(DOWNLOAD_TIMEOUT) + ' секунд). Получено ' + str(size) + ' байт. Проверьте скорость HTTPS-источника или используйте внутреннее зеркало.')
                    chunks.append(piece)
        except OSError:
            if attempt == 2:
                raise
            continue
        if expected_size is None or size == expected_size:
            break
        if size > expected_size:
            raise ValueError('Размер загрузки OVAL не совпадает с HTTP-ответом.')
    if expected_size is not None and size != expected_size:
        raise ValueError('Источник оборвал загрузку OVAL; файл получен не полностью после трёх попыток.')
    raw = b''.join(chunks)
    # Check pinned bytes before allocating a potentially large XML tree.
    if hashlib.sha256(raw).hexdigest() != config['sha256']:
        raise ValueError('SHA-256 OVAL не совпадает с ожидаемым: выполнение остановлено.')
    root = safe_xml(raw)
    source_definitions(root)
    metadata, reasons = source_metadata(root, raw, config)
    write_bytes(output, raw)
    result = {'ok': True, 'path': output, 'database': metadata, 'warnings': reasons}
    if validate:
        binary = shutil.which('oscap')
        if not binary:
            raise ValueError('OpenSCAP не установлен на control node: XML нельзя проверить перед передачей.')
        result['sourceValidation'] = validate_for_transfer(binary, output, metadata['sha256'], len(raw), os.path.dirname(output))
    return result


def write_bytes(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)


def write_json(path, value):
    # Large vendor feeds produce large evidence snapshots. Stream JSON rather
    # than keeping both a complete Unicode string and its UTF-8 copy in RAM.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def run_oscap(command, directory, timeout=900, capture_stdout=False, environment=None):
    # Bound logs and result files as well as run time; kill the entire probe
    # process group on timeout. No shell, package installation or fetch option.
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT_BYTES, MAX_RESULT_BYTES))
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, cwd=directory, stdout=stdout, stderr=stderr, env=environment,
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


def platform_applicability(affected):
    """Reject obvious foreign OS metadata without inventing release support.

    Labels are a conservative contradiction check, not evidence that unknown
    platforms or a named Astra release are certified as applicable.
    """
    platforms = [label for group in affected for label in group['platforms']]
    normalized = [re.sub(r'[_-]+', ' ', label.lower()) for label in platforms]
    astra = any(re.search(r'\bastra(?:\s+linux)?\b|\bastralinux\b|астра(?:\s+линукс)?', label)
                for label in normalized)
    foreign = []
    foreign_cpe_vendors = frozenset(('canonical', 'ubuntu', 'debian', 'redhat', 'centos',
        'fedoraproject', 'suse', 'opensuse', 'oracle', 'rocky', 'rockylinux',
        'almalinux', 'microsoft', 'apple'))
    for original, label in zip(platforms, normalized):
        cpe = re.match(r'^cpe(?::2\.3)?:/?o:([^:]+):', original.lower())
        if (re.search(r'\b(?:ubuntu|debian|red\s*hat|rhel|centos|fedora|(?:open)?suse|'
                      r'oracle\s+linux|rocky(?:\s+linux)?|alma(?:\s*linux)?|'
                      r'windows|mac\s*os(?:\s*x)?|os\s+x|darwin)\b', label)
                or (cpe and cpe.group(1) in foreign_cpe_vendors)):
            foreign.append(original)
    if foreign and not astra:
        return {'status': 'foreign_platform', 'foreignPlatforms': foreign,
                'vendorReleaseApplicability': 'not_verified'}
    return {'status': 'astra_named' if astra else 'not_verified',
            'foreignPlatforms': foreign, 'vendorReleaseApplicability': 'not_verified'}


def severity_assessment(severity, title, description):
    levels = {'critical': 'critical', 'high': 'high', 'important': 'high',
              'medium': 'medium', 'moderate': 'medium', 'low': 'low'}
    if severity:
        level = levels.get(severity.strip().lower())
        return {'level': level, 'source': 'oval_metadata'} if level else None
    if re.search(r'\b(?:chromium|chrome)\b', title, re.I):
        labels = set(m.lower() for m in re.findall(
            r'\(Chromium security severity:\s*(Critical|High|Medium|Low)\)', description, re.I))
        if len(labels) == 1:
            return {'level': labels.pop(), 'source': 'chromium_description'}
    return None


def definition_metadata(node):
    metadata = child(node, 'metadata')
    references = []
    affected = []
    cves = set()
    if metadata is not None:
        for reference in metadata.iter():
            if local_name(reference.tag) == 'affected':
                affected.append({'family': reference.get('family'),
                    'platforms': [node_text(n) for n in reference if local_name(n.tag) == 'platform'],
                    'products': [node_text(n) for n in reference if local_name(n.tag) == 'product']})
            if local_name(reference.tag) == 'reference':
                references.append(dict(reference.attrib))
                identifier = reference.get('ref_id', '').upper()
                if re.match(r'^CVE-\d{4}-\d{4,}$', identifier):
                    cves.add(identifier)
    severity = next((node_text(n) for n in metadata.iter() if local_name(n.tag) == 'severity'), '') if metadata is not None else ''
    return {'id': node.get('id'), 'version': node.get('version'), 'class': node.get('class', ''),
            'title': node_text(child(metadata, 'title')) if metadata is not None else '',
            'description': node_text(child(metadata, 'description')) if metadata is not None else '',
            'references': references, 'affected': affected, 'platformApplicability': platform_applicability(affected),
            'cveIds': sorted(cves), 'vendorSeverity': severity or None,
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
    scanner['unratedVulnerabilityCount'] = sum(f['status'] == 'failed' and f.get('severityUnknown') is True for f in findings)
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
    excluded_platform_count = 0
    for identifier, source in sorted(definitions.items()):
        entry = definition_metadata(source)
        result = mapped.get(identifier)
        status = result.get('result', '') if result is not None else 'missing'
        entry['result'] = status
        foreign_platform = entry['platformApplicability']['status'] == 'foreign_platform'
        if entry['class'] == 'vulnerability':
            vulnerability_count += 1
            if status in ('true', 'false') and not foreign_platform:
                evaluated_vulnerability_count += 1
        entry['resultCriteria'] = xml_evidence(child(result, 'criteria')) if result is not None else None
        scanner['definitionResults'].append(entry)
        counts[status] = counts.get(status, 0) + 1
        if status not in ('true', 'false', 'not applicable'):
            scanner['partialReasons'].append('Не завершено определение ' + identifier + ': ' + status)
        if entry['class'] == 'vulnerability' and foreign_platform:
            excluded_platform_count += 1
            scanner['partialReasons'].append('Определение ' + identifier + ' указывает другую ОС; его результат исключён из CVE-оценки Astra.')
            report['findings'].append(finding(identifier, 'OVAL: проверьте применимость к Astra — ' + (entry['title'] or identifier),
                'manual', 'Метаданные определения указывают другую ОС. Результат OpenSCAP сохранён, но уязвимость Astra по нему не подтверждается.',
                json.dumps({'definitionId': identifier, 'nativeResult': status, 'affected': entry['affected'],
                            'referencedCveIds': entry['cveIds']}, ensure_ascii=False)))
        elif status == 'true' and entry['class'] == 'vulnerability':
            positive_cves.update(entry['cveIds'])
            assessment = severity_assessment(entry['vendorSeverity'], entry['title'], entry['description'])
            risk = ('high' if assessment['level'] == 'critical' else assessment['level']) if assessment else 'info'
            item = finding(identifier, (', '.join(entry['cveIds']) + ': ' if entry['cveIds'] else '') + (entry['title'] or identifier),
                'failed', entry['description'] or 'OpenSCAP подтвердил условия vulnerability-определения OVAL.',
                json.dumps({'definitionId': identifier, 'cveIds': entry['cveIds'], 'result': status,
                            'vendorSeverity': entry['vendorSeverity'], 'criteria': entry['resultCriteria']}, ensure_ascii=False), risk)
            item['severityUnknown'] = risk == 'info'
            if assessment:
                item['severityAssessment'] = assessment
            item['vulnerability'] = {'cveIds': entry['cveIds'], 'definitionId': identifier,
                'severitySource': assessment['source'] if assessment else 'not_provided', 'cvss': None}
            report['findings'].append(item)
        elif status == 'true' and entry['class'] not in ('vulnerability', 'inventory'):
            report['findings'].append(finding(identifier, 'OVAL ' + entry['class'] + ': ' + (entry['title'] or identifier),
                'manual', 'Истинное определение этого класса не преобразуется автоматически в найденную CVE.',
                json.dumps({'class': entry['class'], 'references': entry['references'], 'result': status}, ensure_ascii=False)))
    scanner['resultCounts'] = counts
    scanner['definitionCount'] = len(definitions)
    scanner['vulnerabilityDefinitionCount'] = vulnerability_count
    scanner['evaluatedVulnerabilityDefinitionCount'] = evaluated_vulnerability_count
    scanner['excludedPlatformDefinitionCount'] = excluded_platform_count
    if not vulnerability_count:
        scanner['partialReasons'].append('База не содержит vulnerability-определений: CVE-аудит не выполнен.')
    elif not evaluated_vulnerability_count:
        scanner['partialReasons'].append('Нет vulnerability-определений с допустимой областью и результатом true/false; применимая CVE-оценка отсутствует.')
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
            controller_validated = use_controller_validation(args, config, hashlib.sha256(raw).hexdigest(), scanner)
            if not controller_validated:
                code, detail = run_oscap([binary, 'oval', 'validate', source_path], directory, 600, capture_stdout=True)
                scanner['validationExitCode'] = code
                if code != 0:
                    raise ValueError('Проверка формата OVAL не пройдена: ' + detail)
            command = [binary, 'oval', 'eval', '--results', result_path]
            if controller_validated:
                # These exact pinned bytes already passed mandatory XSD on
                # the controller. Do not repeat the slow old-target validator.
                command.append('--skip-validation')
            code, detail = run_oscap(command + [source_path], directory)
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
    parser.add_argument('--validate', action='store_true')
    parser.add_argument('--source-validation', default='{}')
    parser.add_argument('--output', required=True)
    parser.add_argument('--inventory-host', default='localhost')
    parser.add_argument('--run-id', default='manual')
    parser.add_argument('--reason', default='Источник OVAL недоступен.')
    args = parser.parse_args()
    if args.command == 'prepare':
        try:
            result = prepare(parse_config(args.config), args.output, validate=args.validate)
        except (OSError, ValueError, ET.ParseError, UnicodeError) as error:
            result = {'ok': False, 'error': str(error)}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    report = evaluate(args) if args.command == 'evaluate' else finish(empty_report(args, args.reason))
    # Existing report IDs should be unique; no silent overwrite or symlink follow.
    write_json(args.output, report)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
