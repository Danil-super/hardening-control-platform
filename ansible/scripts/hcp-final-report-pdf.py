#!/usr/bin/env python3
"""Render a bounded, server-projected HCP final report as a PDF.

The caller supplies a sanitized snapshot through stdin.  This helper never
opens report files, credentials, inventory or remote hosts on its own.
"""
from __future__ import print_function

import html
import io
import json
import os
import sys

MAX_INPUT = 1024 * 1024


def clean(value, limit=3000):
    if value is None:
        return '—'
    if not isinstance(value, str):
        value = str(value)
    value = ''.join(char if ord(char) >= 32 or char in '\n\t' else ' ' for char in value)
    return value[:limit].strip() or '—'


def esc(value, limit=3000):
    return html.escape(clean(value, limit)).replace('\n', '<br/>')


def item_label(value):
    labels = {
        'discovered': 'Найдено', 'proposed': 'Предложено', 'agreed': 'Согласовано',
        'completed': 'Выполнено', 'confirmed': 'Подтверждено', 'accepted_risk': 'Принято как риск',
    }
    return labels.get(value, clean(value, 60))


def risk_label(value):
    return {'high': 'Высокий', 'medium': 'Средний', 'low': 'Низкий', 'info': 'Информационный'}.get(value, clean(value, 60))


def list_value(values, fallback='—'):
    if not isinstance(values, list) or not values:
        return fallback
    return '; '.join(clean(value, 240) for value in values[:50])


def font_path(name):
    candidates = (
        '/usr/share/fonts/truetype/dejavu/' + name,
        '/usr/share/fonts/dejavu/' + name,
    )
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise RuntimeError('Шрифт DejaVu не установлен.')


def render(snapshot):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    pdfmetrics.registerFont(TTFont('HCPDejaVu', font_path('DejaVuSans.ttf')))
    pdfmetrics.registerFont(TTFont('HCPDejaVuBold', font_path('DejaVuSans-Bold.ttf')))
    styles = getSampleStyleSheet()
    body = ParagraphStyle('HCPBody', parent=styles['BodyText'], fontName='HCPDejaVu', fontSize=9, leading=13, spaceAfter=5)
    small = ParagraphStyle('HCPSmall', parent=body, fontSize=7.5, leading=10, textColor=colors.HexColor('#334155'))
    title = ParagraphStyle('HCPTitle', parent=styles['Title'], fontName='HCPDejaVuBold', fontSize=19, leading=24, alignment=TA_CENTER, textColor=colors.HexColor('#0f172a'), spaceAfter=12)
    heading = ParagraphStyle('HCPHeading', parent=styles['Heading2'], fontName='HCPDejaVuBold', fontSize=13, leading=17, textColor=colors.HexColor('#0f172a'), spaceBefore=12, spaceAfter=6)
    subheading = ParagraphStyle('HCPSubheading', parent=styles['Heading3'], fontName='HCPDejaVuBold', fontSize=10, leading=14, textColor=colors.HexColor('#0f172a'), spaceBefore=8, spaceAfter=3)

    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=17 * mm, bottomMargin=18 * mm,
                                 title='Итоговый отчёт HCP', author=clean(snapshot.get('subject', {}).get('specialist'), 200))
    story = []
    subject = snapshot.get('subject', {}) if isinstance(snapshot.get('subject'), dict) else {}
    story.append(Paragraph('Итоговый отчёт по контролю безопасности', title))
    story.append(Paragraph('HCP · сформирован ' + esc(snapshot.get('createdAt')) + ' · идентификатор ' + esc(snapshot.get('id')), small))
    story.append(Spacer(1, 5))
    overview = [
        [Paragraph('<b>Заказчик</b>', body), Paragraph(esc(subject.get('clientName')), body)],
        [Paragraph('<b>Проект</b>', body), Paragraph(esc(subject.get('projectName')), body)],
        [Paragraph('<b>Период работ</b>', body), Paragraph(esc(subject.get('period')), body)],
        [Paragraph('<b>Специалист</b>', body), Paragraph(esc(subject.get('specialist')), body)],
        [Paragraph('<b>Целевой хост</b>', body), Paragraph(esc(snapshot.get('hostAlias')), body)],
    ]
    table = Table(overview, colWidths=(42 * mm, 136 * mm), hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e2e8f0')), ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#cbd5e1')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
    story.append(table)

    story.append(Paragraph('1. Область, метод и ограничения', heading))
    scope = snapshot.get('scope', {}) if isinstance(snapshot.get('scope'), dict) else {}
    story.append(Paragraph('В область включён только указанный целевой хост и отчёты HCP, перечисленные в приложении. Использованные виды проверок: ' + esc(list_value(scope.get('auditModes'), 'нет доступных отчётов')) + '.', body))
    story.append(Paragraph('Выводы основаны на доступных на момент формирования доказательствах. Совпадение CVE, версии или баннера не является само по себе подтверждением применимости. Astra OVAL оценивает только выбранную базу; её происхождение и SHA-256 фиксируются в исходном отчёте, но подпись производителя и полнота всех CVE автоматически не подтверждаются.', body))
    story.append(Paragraph('HCP не хранит в этом отчёте пароли, приватные SSH-ключи, пути к резервным копиям, команды изменения или необработанный вывод удалённых систем.', body))

    coverage = snapshot.get('coverage', []) if isinstance(snapshot.get('coverage'), list) else []
    story.append(Paragraph('2. Покрытие и свежесть аудита', heading))
    if coverage:
        rows = [[Paragraph('<b>Отчёт</b>', small), Paragraph('<b>Тип</b>', small), Paragraph('<b>Время</b>', small), Paragraph('<b>Состояние</b>', small)]]
        for item in coverage[:80]:
            if not isinstance(item, dict):
                continue
            state = 'полный, свежий' if item.get('fresh') and not item.get('partial') and item.get('available') else 'частичный, недоступный или устаревший'
            rows.append([Paragraph(esc(item.get('reportId'), 120), small), Paragraph(esc(item.get('mode'), 70), small), Paragraph(esc(item.get('createdAt'), 100), small), Paragraph(esc(state, 100), small)])
        coverage_table = Table(rows, colWidths=(49 * mm, 29 * mm, 52 * mm, 48 * mm), repeatRows=1)
        coverage_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')), ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#cbd5e1')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 4), ('RIGHTPADDING', (0, 0), (-1, -1), 4), ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4)]))
        story.append(coverage_table)
    else:
        story.append(Paragraph('Для хоста не найдено отчётов, пригодных для сводки покрытия.', body))

    findings = snapshot.get('findings', []) if isinstance(snapshot.get('findings'), list) else []
    story.append(Paragraph('3. Находки и решения', heading))
    if findings:
        for index, item in enumerate(findings[:120], 1):
            if not isinstance(item, dict):
                continue
            content = [Paragraph(str(index) + '. ' + esc(item.get('title'), 300) + ' <font color="#475569">[' + esc(risk_label(item.get('risk')), 50) + '; ' + esc(item_label(item.get('status')), 80) + ']</font>', subheading),
                       Paragraph('<b>Описание:</b> ' + esc(item.get('description'), 1400), body),
                       Paragraph('<b>Рекомендация:</b> ' + esc(item.get('recommendation'), 1400), body)]
            if item.get('owner') or item.get('dueAt') or item.get('approvalReference'):
                content.append(Paragraph('<b>Решение:</b> ответственный — ' + esc(item.get('owner')) + '; срок — ' + esc(item.get('dueAt')) + '; согласование — ' + esc(item.get('approvalReference'), 400) + '.', body))
            if item.get('implementationNote'):
                content.append(Paragraph('<b>Выполнение:</b> ' + esc(item.get('implementationNote'), 1400), body))
            if item.get('verificationReportId'):
                content.append(Paragraph('<b>Повторная проверка:</b> ' + esc(item.get('verificationReportId'), 180) + '.', body))
            evidence = item.get('evidence', []) if isinstance(item.get('evidence'), list) else []
            sources = []
            for source in evidence[:8]:
                if isinstance(source, dict):
                    sources.append(clean(source.get('reportId'), 120) + ' / ' + clean(source.get('findingId'), 120))
            content.append(Paragraph('<b>Технические источники:</b> ' + esc('; '.join(sources) if sources else 'не зафиксированы', 1200), small))
            story.append(KeepTogether(content))
    else:
        story.append(Paragraph('Пункты плана устранения не зафиксированы. Это не означает отсутствия уязвимостей: проверьте раздел покрытия и исходные отчёты.', body))

    unplanned = snapshot.get('unplannedFindings', []) if isinstance(snapshot.get('unplannedFindings'), list) else []
    if unplanned:
        story.append(Paragraph('Непереведённые в план свежие наблюдения', subheading))
        for item in unplanned[:80]:
            if isinstance(item, dict):
                story.append(Paragraph('• ' + esc(item.get('title'), 300) + ' [' + esc(risk_label(item.get('risk')), 50) + ']. ' + esc(item.get('recommendation'), 800), body))

    transactions = snapshot.get('transactions', []) if isinstance(snapshot.get('transactions'), list) else []
    story.append(Paragraph('4. Выполненные управляемые изменения', heading))
    if transactions:
        for transaction in transactions[:80]:
            if not isinstance(transaction, dict):
                continue
            story.append(Paragraph('<b>' + esc(transaction.get('action'), 180) + '</b> — ' + esc(transaction.get('status'), 80) + '. Основание: ' + esc(transaction.get('reason'), 900) + '. Исходный/повторный отчёт: ' + esc(transaction.get('preAuditReportId')) + ' / ' + esc(transaction.get('postAuditReportId')) + '.', body))
    else:
        story.append(Paragraph('В HCP не зафиксировано управляемых изменений для этого хоста. Ручные действия вне HCP должны подтверждаться отдельными документами заказчика.', body))

    integrity = snapshot.get('integrity', {}) if isinstance(snapshot.get('integrity'), dict) else {}
    story.append(Paragraph('5. Целостность и приложение доказательств', heading))
    story.append(Paragraph('Цепочка журнала HCP: ' + esc('проверена' if integrity.get('valid') else 'требует проверки') + '; записей: ' + esc(integrity.get('entries')) + '; защита полезной нагрузки: ' + esc('полная' if integrity.get('payloadProtected') else 'частично историческая') + '.', body))
    story.append(Paragraph('Снимок источников: SHA-256 ' + esc(snapshot.get('sourceManifestSha256'), 90) + '. Контрольная сумма этого PDF зафиксирована в записи экспорта HCP с данным идентификатором. Номера и контрольные суммы исходных JSON-отчётов находятся в сохранённом снимке. Цепочка HMAC защищает события HCP; исходные JSON фиксируются через этот манифест, а не подписываются по отдельности.', body))
    manifest = snapshot.get('sourceManifest', []) if isinstance(snapshot.get('sourceManifest'), list) else []
    if manifest:
        story.append(Paragraph('Исходные отчёты', subheading))
        for item in manifest[:150]:
            if isinstance(item, dict):
                story.append(Paragraph('• ' + esc(item.get('id'), 130) + ' · ' + esc(item.get('mode'), 80) + ' · ' + esc(item.get('createdAt'), 100) + ' · SHA-256 ' + esc(item.get('sha256'), 90), small))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont('HCPDejaVu', 7)
        canvas.setFillColor(colors.HexColor('#475569'))
        canvas.drawString(16 * mm, 10 * mm, 'HCP · итоговый отчёт · ' + clean(snapshot.get('id'), 80))
        canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, 'Страница %d' % canvas.getPageNumber())
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError('Снимок отчёта превышает допустимый размер.')
    snapshot = json.loads(raw.decode('utf-8'))
    if not isinstance(snapshot, dict):
        raise ValueError('Снимок отчёта имеет неверный формат.')
    output = render(snapshot)
    if not output.startswith(b'%PDF-') or len(output) > 12 * 1024 * 1024:
        raise ValueError('Не удалось сформировать корректный PDF.')
    sys.stdout.buffer.write(output)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # The HTTP layer intentionally maps any internal renderer failure to a
        # generic message and never exposes a filesystem path or report data.
        sys.exit(1)
