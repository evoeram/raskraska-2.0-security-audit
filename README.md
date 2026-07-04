# 🎨 Раскраска 2.0 / Raskraska 2.0

WPF-приложение для раскрашивания (.NET Framework 4.8).

<!-- Replace with real description when ready -->

---

## 📦 Release / Сборка

Исполняемые файлы (`Раскраска.exe`, `Раскраска_PATCHED.exe`, `*.dll`) **не коммитятся в репозиторий**.
Распространяются через [GitHub Releases](../../releases).

Чтобы получить готовую сборку — скачайте последний релиз со страницы Releases.

### Зависимости

- **Runtime:** .NET Framework 4.8+ (входит в Windows 10/11)
- **OS:** Windows 7 SP1 / 8.1 / 10 / 11
- **Сторонние библиотеки** (поставляются вместе с релизом):
  - `Xceed.WpfToolkit.dll` — расширенные WPF-контролы
  - `PdfSharp.dll`, `PdfSharp.Charting.dll` — генерация PDF
  - `SmthForContours.dll` — внутренние утилиты для работы с контурами
  - `CommonClassesToConnectionWithServer.dll` — WCF-клиент для серверной части
  - `Xceed.Wpf.Toolkit.dll` — UI toolkit

### Запуск

1. Распакуйте архив релиза в любую папку
2. Запустите `Раскраска.exe`
3. При первом запуске приложение соединится с сервером для проверки лицензии (требуется интернет)

---

## 🔐 Security Audit

В каталоге `security_audit/` находятся отчёт о black-box-аудите безопасности приложения
и proof-of-concept скрипт `CREATE_PATCH.py`, демонстрирующий уязвимость из-за отсутствия
защиты IL-кода в управляемом .NET-бинарнике.

### ⚠️ ДИСКЛЕЙМЕР / DISCLAIMER

> **`CREATE_PATCH.py` предоставляется ИСКЛЮЧИТЕЛЬНО в образовательных целях
> для демонстрации уязвимостей, связанных с отсутствием Anti-Tamper в .NET-сборках.**
>
> Использование скрипта для обхода лицензионных ограничений
> коммерческого программного обеспечения является нарушением
> **[ст. 146 УК РФ](https://www.consultant.ru/document/cons_doc_LAW_10699/)**
> и международных соглашений об авторском праве.
>
> Авторы проекта не несут ответственности за неправомерное использование.

### Что показывает аудит

| Аспект | Статус |
|---|---|
| Обфускация IL-кода | ❌ Отсутствует |
| Anti-Tamper | ❌ Отсутствует |
| Authenticode-подпись | ❌ Отсутствует |
| Integrity Check (самопроверка) | ❌ Отсутствует |
| Клиентская логика лицензирования | ❌ Полностью на клиенте |

Подробности — в [security_audit/SECURITY_AUDIT_REPORT.md](security_audit/SECURITY_AUDIT_REPORT.md).

### Запуск `CREATE_PATCH.py` (для исследователей безопасности)

```bash
pip install pefile dnfile
python security_audit/CREATE_PATCH.py --input path/to/Раскраска.exe --output patched.exe
```

Скрипт применяет 13 type-safe IL-патчей к методам класса `Бисерок.RegistryWork`,
проверяющим лицензию. Используется прямой бинарный патч PE-файла без Mono.Cecil/dnSpy.

---

## 🛠️ Рекомендуемые улучшения (см. отчёт)

1. **ConfuserEx / .NET Reactor** — обфускация + Anti-Tamper
2. **Authenticode EV Certificate** — подпись бинарника
3. **Self-Integrity Check** — SHA-256 при запуске
4. **Серверная валидация лицензии** — перенос принятия решений на сервер
5. **RSA/ECC проверка ответов сервера** — асимметричная криптография
6. **.NET 8 Native AOT** — полный переход на машинный код

---

## 📄 Лицензия

Это коммерческое программное обеспечение. Все права защищены.

Распространение, модификация или обратная разработка запрещены
без письменного разрешения правообладателя.

---

## 👤 Автор / Author

**Звезинцев Андрей / AndZvezintsev**

---

## 📚 Ссылки

- [Security Audit Report](security_audit/SECURITY_AUDIT_REPORT.md)
- [PoC Patch Script](security_audit/CREATE_PATCH.py)
