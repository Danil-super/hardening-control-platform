#!/usr/bin/env python3
"""Translate public finding descriptions locally; never evaluate vulnerability risk."""
import collections
import json
import os
import re
import sys

MAX_INPUT = 80_000
MAX_TEXT = 20_000
IDENTIFIERS = re.compile(r'\b(?:CVE-\d{4}-\d{4,}|CWE-\d+|\d+(?:\.\d+){1,}(?:[a-zA-Z][a-zA-Z0-9]*)?)\b')
ENGINE = 'argos-en-ru-1.9-glossary-v4'
GLOSSARY = {
    'CPE Inventory': 'Инвентаризация CPE',
    'Services': 'Службы',
    'Traceroute': 'Трассировка маршрута',
    'DNS Server Detection (TCP)': 'Обнаружение DNS-сервера (TCP)',
    'Multiple Vulnerabilities': 'несколько уязвимостей',
    'Unspecified Vulnerability': 'неуточнённая уязвимость',
    'MitM Vulnerability': 'уязвимость атаки «посредник» (MitM)',
    'Command Injection Vulnerability': 'уязвимость внедрения команд',
    'Privilege Escalation Vulnerability': 'уязвимость повышения привилегий',
    'Information Disclosure Vulnerability': 'уязвимость раскрытия информации',
    'RCE Vulnerability': 'уязвимость удалённого выполнения кода (RCE)',
    'DoS Vulnerability': 'уязвимость отказа в обслуживании (DoS)',
    'Installed version': 'Установленная версия',
    'Fixed version': 'Версия с исправлением',
    'Installation path / port': 'Путь установки / порт',
    'Update to version': 'Обновите до версии',
    'OpenBSD': 'OpenBSD', 'OpenSSH': 'OpenSSH', 'Diffie-Hellman': 'Диффи — Хеллмана',
    'DHE': 'DHE', 'ECDHE': 'ECDHE', 'RSA': 'RSA', 'MaxStartups': 'MaxStartups',
    'use after free': 'использование памяти после освобождения',
    'use-after-free': 'использование памяти после освобождения',
    'out of bounds write': 'запись за пределами выделенной памяти',
    'out-of-bounds write': 'запись за пределами выделенной памяти',
    'out of bounds read': 'чтение за пределами выделенной памяти',
    'out-of-bounds read': 'чтение за пределами выделенной памяти',
    'out of bounds memory access': 'доступ к памяти за пределами допустимых границ',
    'heap corruption': 'повреждение памяти в куче',
    'heap buffer overflow': 'переполнение буфера в куче',
    'buffer overflow': 'переполнение буфера',
    'integer overflow': 'целочисленное переполнение',
    'integer underflow': 'выход целочисленного значения ниже допустимой границы',
    'type confusion': 'смешение типов',
    'inappropriate implementation': 'ошибка реализации',
    'insufficient validation': 'недостаточная проверка',
    'uninitialized use': 'использование неинициализированных данных',
    'data race': 'гонка данных',
    'race condition': 'состояние гонки',
    'sandbox escape': 'выход за пределы песочницы',
    'denial of service': 'отказ в обслуживании',
    'arbitrary code execution': 'выполнение произвольного кода',
    '(Chromium security severity: Critical)': '(Критичность по оценке Chromium: критическая)',
    '(Chromium security severity: High)': '(Критичность по оценке Chromium: высокая)',
    '(Chromium security severity: Medium)': '(Критичность по оценке Chromium: средняя)',
    '(Chromium security severity: Low)': '(Критичность по оценке Chromium: низкая)',
}


def chromium_description(text):
    """Translate the standard advisory sentence without losing technical nouns.

    Only exact, complete templates qualify; other prose uses the local model.
    Versions, components, attacker preconditions and effects come from input.
    """
    weaknesses = {
        'Use after free': ('Использование памяти после освобождения', 'позволяло'),
        'Out of bounds write': ('Запись за пределами выделенной памяти', 'позволяла'),
        'Out of bounds read': ('Чтение за пределами выделенной памяти', 'позволяло'),
        'Heap buffer overflow': ('Переполнение буфера в куче', 'позволяло'),
        'Type confusion': ('Смешение типов', 'позволяло'),
        'Inappropriate implementation': ('Ошибка реализации', 'позволяла'),
        'Insufficient validation': ('Недостаточная проверка', 'позволяла'),
    }
    attackers = {
        'a remote attacker': 'удалённому злоумышленнику',
        'a remote attacker who had compromised the renderer process': 'удалённому злоумышленнику, скомпрометировавшему процесс рендеринга,',
    }
    effects = {
        'perform out of bounds memory access': 'обращаться к памяти за пределами допустимых границ',
        'perform out of bounds memory read': 'читать память за пределами допустимых границ',
        'potentially exploit heap corruption': 'потенциально использовать повреждение памяти в куче',
        'exploit heap corruption': 'использовать повреждение памяти в куче',
        'potentially perform a sandbox escape': 'потенциально выйти за пределы песочницы',
        'perform a sandbox escape': 'выйти за пределы песочницы',
        'bypass site isolation': 'обойти изоляцию сайтов',
    }
    match = re.fullmatch(
        r'(?P<weakness>.+?) in (?P<component>.+?) in Google Chrome(?P<desktop> on Desktop)? '
        r'prior to (?P<version>\d+(?:\.\d+)+) allowed (?P<attacker>.+?) to (?P<effect>.+?) '
        r'via a crafted HTML page\.\s*\(Chromium security severity: (?P<severity>Critical|High|Medium|Low)\)', text)
    if not match:
        return None
    fields = match.groupdict()
    if fields['weakness'] not in weaknesses or fields['attacker'] not in attackers or fields['effect'] not in effects:
        return None
    weakness, verb = weaknesses[fields['weakness']]
    product = 'настольной версии Google Chrome' if fields['desktop'] else 'браузера Google Chrome'
    severity = GLOSSARY['(Chromium security severity: ' + fields['severity'] + ')']
    return (weakness + ' в компоненте ' + fields['component'] + ' ' + product + ' до версии ' + fields['version']
            + ' ' + verb + ' ' + attackers[fields['attacker']] + ' ' + effects[fields['effect']]
            + ' с помощью специально сформированной HTML-страницы. ' + severity)


def protect_terms(text):
    if 'HCPTERM' in text:
        raise ValueError('Reserved translation marker in source')
    replacements = dict(GLOSSARY)
    for token in IDENTIFIERS.findall(text) + re.findall(r'\b\d{1,5}/(?:tcp|udp)\b|\b[a-z0-9]+(?:-[a-z0-9]+){2,}(?:@[a-z0-9.-]+)?\b', text):
        replacements.setdefault(token, token)
    # Preserve named software components such as Dawn and Serviceworker.
    for component in re.findall(r'\bin ([^\n.]{1,100}?) in Google Chrome\b', text):
        replacements.setdefault(component, component)
    lookup = {key.lower(): value for key, value in replacements.items()}
    pattern = re.compile(r'(?<!\w)(?:' + '|'.join(re.escape(key) for key in sorted(replacements, key=len, reverse=True)) + r')(?!\w)', re.I)
    protected = {}

    def replace(match):
        marker = 'HCPTERM%03d' % len(protected)
        protected[marker] = lookup[match.group(0).lower()]
        return marker
    return pattern.sub(replace, text), protected


def restore_terms(text, protected):
    for marker, term in protected.items():
        if text.count(marker) != 1:
            raise ValueError('Translation dropped or repeated a technical term')
        text = text.replace(marker, term)
    if 'HCPTERM' in text:
        raise ValueError('Unexpected translation marker')
    return text[:1].upper() + text[1:]


def verify_identifiers(original, translated):
    if collections.Counter(IDENTIFIERS.findall(original)) != collections.Counter(IDENTIFIERS.findall(translated)):
        raise ValueError('Translation changed a vulnerability identifier or version')
    if not re.search('[а-яА-ЯёЁ]', translated):
        raise ValueError('Translation did not produce Russian text')


def translate(text, model_path):
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
        raise ValueError('Invalid description')
    known = next((value for key, value in GLOSSARY.items() if key.casefold() == text.strip().casefold()), None)
    if known:
        verify_identifiers(text, known)
        return known
    standard = chromium_description(text)
    if standard:
        verify_identifiers(text, standard)
        return standard
    import ctranslate2
    import sentencepiece
    tokenizer = sentencepiece.SentencePieceProcessor(model_file=os.path.join(model_path, 'sentencepiece.model'))
    translator = ctranslate2.Translator(os.path.join(model_path, 'model'), device='cpu', compute_type='int8', inter_threads=1, intra_threads=2)
    # Version dots are not sentence boundaries. Keep sentences complete and
    # reject oversized input instead of allowing the engine to truncate it.
    paragraphs = text.split('\n')
    translated = []
    for paragraph in paragraphs:
        if not paragraph.strip():
            translated.append('')
            continue
        protected_text, protected = protect_terms(paragraph.strip())
        sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z(])', protected_text)
        tokens = [tokenizer.encode(sentence, out_type=str) for sentence in sentences]
        if any(len(sentence) > 1024 for sentence in tokens):
            raise ValueError('Description sentence exceeds model context')
        results = translator.translate_batch(tokens, beam_size=4, max_input_length=1024, max_decoding_length=2048)
        lines = []
        for result in results:
            if len(result.hypotheses[0]) >= 2048:
                raise ValueError('Translation reached its output limit')
            lines.append(tokenizer.decode(result.hypotheses[0]))
        translated.append(restore_terms(' '.join(lines), protected))
    output = '\n'.join(translated).strip()
    verify_identifiers(text, output)
    return output


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError('Request is too large')
    data = json.loads(raw.decode('utf-8'))
    model_path = '/opt/hcp-tools/translation/model'
    text = translate(data.get('text'), model_path)
    sys.stdout.write(json.dumps({'text': text, 'engine': ENGINE}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Descriptions and internal paths must not escape through diagnostics.
        sys.exit(1)
