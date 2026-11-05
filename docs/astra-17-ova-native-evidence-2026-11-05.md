# Оригинальный подтверждённый нативный SSH-прогон Astra 1.7.6.15

**Дата:** 5 ноября 2026 г.  
**Прогон:** [GitHub Actions #42027952736](https://github.com/Danil-super/hardening-control-platform/actions/runs/42027952736) — `success`, PR #69 (объединён с `main`, commit `acb4a1540cbf8f9c2a5151e392d68fed0c173ea1`).

Из GitHub Actions artifact `native-astra17-ova-ssh-only` (artifact ID
`13415048586`) **оригинальным содержимым** извлечён очищенный
`hcp-astra17-ova-public-result.json`, 1794 байта,
SHA-256: `ba0cbce8203fd2c23b531c1f9cb3aad85bddb21d8ebd5eb3189a69d2650de2fb`.

Его **точные оригинальные байты, без реконструкции дат или значений**,
сохранены в [evidence/astra17-ova-ssh-run-42027952736.json](evidence/astra17-ova-ssh-run-42027952736.json).
Архивирован только уже публичный **санитизированный** JSON CI,
не целевой диск, не исходный machine-id, не ssh-ключи или
закрытые журналы. Срок хранения самого ZIP GitHub Actions — 14 дней;
эта репозиторная копия позволяет проверить исходный протокол дольше.

## Непосредственно подтверждено

- Оригинальный официальный `alse-1.7.6.uu2-base-virtualbox-mg15.3.1-amd64.ova`,
  **427995648** байт, SHA-256
  `72ccb335f4c46b5b6d1410cfe0c08f648f95a5e6fd1026f6e0b2d65d8b7ebf6e`.
- Извлечён один подлинный VMDK размером **427984384** байта,
  преобразован в приватный QCOW2, запущен QEMU/**KVM**.
- Реальный гость через SSH наблюдал `ID=astra`,
  `/etc/astra_version=1.7.6`,
  `/etc/astra/build_version=1.7.6.15`, архитектуру
  `x86_64`, существование ядра и machine-id.
- Второе независимое соединение с тем же закреплённым SSH ключом
  подтвердило идентичность временного гостя.

## Чего этот результат не доказывает

- Оригинальный OVA SHA получен **из того же Artifactory**, что исходный
  файл, а не из независимой цифровой подписи Astra.
- SSH trust — только первичная привязка к **собственной одноразовой**
  машине; фабричная учётная запись на реальных серверах недопустима.
- Не выполнялись ни **18 OpenSCAP правил**, ни вендорский
  **OVAL 1.7**, ни харденинг и полноценный откат,
  ни штатный мастер HCP/asset-binding на пользовательской Ubuntu.
- Нельзя закрывать задачи [#40](https://github.com/Danil-super/hardening-control-platform/issues/40),
  [#38](https://github.com/Danil-super/hardening-control-platform/issues/38) или
  [#43](https://github.com/Danil-super/hardening-control-platform/issues/43)
  по одной проверке SSH.

**Следующая отдельная задача:** [PR #72](https://github.com/Danil-super/hardening-control-platform/pull/72)
— попытка нативного запуска штатных HCP Ansible, инвентаризации
и исходного OpenSCAP 18-rule трёхэтапного эксперимента.
Её результат следует проверять отдельно, не переписывая этот
успешный узкий SSH-протокол.
