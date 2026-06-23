#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_rules.py — классификатор находок web-уязвимостей (требования 5, 3 v1.4.0).

ПЕРЕРАБОТКА v1.4.0 (требование 3) — устранение ложных «критичных»:
  * catch-all detection: если сервер отвечает 200 на заведомо несуществующие
    пути, словарные находки по путям подавляются (см. webscan.probe_catch_all);
  * КОНТЕНТНАЯ ВАЛИДАЦИЯ: путь считается реальной находкой только если в теле
    ответа есть ожидаемые маркеры (.env → KEY=VALUE; /.git/config → "[core]";
    phpinfo → "phpinfo()"; backup.sql → SQL; admin → форма входа);
  * АДЕКВАТНЫЙ severity + поле «Обоснование severity» (severity_reason):
      - security.txt → info (это текстовый файл, не админ-панель);
      - страницы входа/login → info/warning (наличие ≠ компрометация);
      - ПОДТВЕРЖДЁННЫЕ .env/.git/backup с секретами → critical;
  * полные кликабельные URL в каждой находке (url);
  * указание утилиты-источника (tool);
  * без наивного keyword-матчинга RCE/XSS (раньше «Признаки XSS (nmap-http)»
    без деталей давали ложные critical) — теперь только структурные находки;
  * дедупликация выполняется на стороне webscan/scanner.

Уровни severity: critical | warning | info.
"""

import re

# ----------------------- наборы признаков -----------------------

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (Strict-Transport-Security)",
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy (CSP)",
    "x-content-type-options": "X-Content-Type-Options",
}

# Админские/служебные панели. Наличие страницы входа САМО ПО СЕБЕ не критично
# (треб. 3) — это info/warning, требует проверки content-валидацией.
ADMIN_PATHS = (
    "/admin", "/administrator", "/wp-admin/", "/phpmyadmin/", "/manager/html",
    "/login", "/user/login", "/admin/login", "/cpanel", "/webmail",
    "/console", "/jenkins", "/grafana", "/kibana", "/_cat", "/actuator",
    "/server-status", "/server-info",
)
# Тестовые/отладочные пути.
TEST_PATHS = (
    "/test", "/test.php", "/dev", "/staging", "/debug", "/phpinfo.php",
    "/info.php", "/example", "/demo", "/backup", "/old", "/tmp",
)
# Конфигурационные/backup-файлы. critical ТОЛЬКО при подтверждении содержимым.
SECRET_FILES = (
    "/.git/config", "/.git/HEAD", "/.env", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/wp-config.php.bak", "/config.php.bak",
    "/.htpasswd", "/.svn/entries", "/web.config.bak", "/backup.zip",
    "/backup.tar.gz", "/.DS_Store",
)
# security.txt — отдельно: это ОЖИДАЕМЫЙ текстовый файл (RFC 9116), severity=info.
SECURITY_TXT = "/.well-known/security.txt"

# Контентные маркеры для подтверждения реальной находки (треб. 3).
# path-substring → (regex по телу ответа, человекочитаемое имя маркера)
CONTENT_MARKERS = {
    "/.env": (re.compile(r"^[A-Z0-9_]+\s*=", re.M),
              "переменные окружения KEY=VALUE"),
    "/.git/config": (re.compile(r"\[core\]", re.I),
                     "секция [core] git-конфига"),
    "/.git/head": (re.compile(r"ref:\s*refs/", re.I),
                   "ссылка ref: refs/ (git HEAD)"),
    "/.htpasswd": (re.compile(r":\$|:[A-Za-z0-9./]{13}$", re.M),
                   "хэши паролей"),
    "/.svn/entries": (re.compile(r"^\d+\s*$", re.M), "формат svn entries"),
    "phpinfo": (re.compile(r"phpinfo\(\)|PHP Version", re.I),
                "вывод phpinfo()"),
    "/info.php": (re.compile(r"phpinfo\(\)|PHP Version", re.I),
                  "вывод phpinfo()"),
    ".sql": (re.compile(r"(?i)\b(insert into|create table|drop table|"
                        r"-- mysql dump)\b"), "SQL-дамп"),
    ".bak": (re.compile(r"<\?php|password|define\(", re.I),
             "исходный код/секреты в backup"),
    ".zip": (re.compile(r"^PK\x03\x04"), "сигнатура ZIP-архива"),
    ".tar.gz": (re.compile(r"^\x1f\x8b"), "сигнатура gzip-архива"),
    "/.ds_store": (re.compile(r"^\x00\x00\x00\x01Bud1", re.S),
                   "сигнатура .DS_Store"),
}

# Маркер формы входа (для админ-панелей).
LOGIN_FORM_RE = re.compile(
    r"(?is)<form[^>]*>.*?(<input[^>]+type=[\"']?password)", )
LOGIN_HINT_RE = re.compile(
    r"(?i)(войти|вход|sign\s*in|log\s*in|username|password|пароль|логин)")


def _norm(s):
    return (s or "").strip().lower()


# ----------------------- security-headers -----------------------

def classify_security_headers(present_headers, is_https=True):
    """Отсутствующие security-headers (severity=warning, с обоснованием)."""
    findings = []
    present = {_norm(h) for h in (present_headers or [])}
    for key, label in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and not is_https:
            continue
        if key not in present:
            findings.append({
                "severity": "warning",
                "category": "headers",
                "title": f"Отсутствует security-header: {label}",
                "detail": f"В ответе сервера не обнаружен заголовок «{label}».",
                "recommendation": _header_recommendation(key),
                "tool": "curl",
                "severity_reason": ("Отсутствие защитного заголовка повышает "
                                    "риск атак (clickjacking/MIME-sniffing/"
                                    "downgrade), но не является прямой "
                                    "компрометацией — уровень warning."),
            })
    return findings


def _header_recommendation(key):
    rec = {
        "strict-transport-security":
            "Включите HSTS: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload.",
        "x-frame-options":
            "Добавьте X-Frame-Options: DENY (или SAMEORIGIN) против "
            "clickjacking.",
        "content-security-policy":
            "Настройте Content-Security-Policy, ограничив источники скриптов/"
            "стилей и запретив inline-скрипты.",
        "x-content-type-options":
            "Добавьте X-Content-Type-Options: nosniff против MIME-sniffing.",
    }
    return rec.get(key, "")


# ----------------------- классификация путей (с контентом) -----------------------

def _content_confirms(path, body):
    """Подтверждает ли тело ответа реальную находку по пути.

    Возвращает (confirmed: bool, marker_name: str|None).
    """
    p = _norm(path)
    body = body or ""
    for key, (rx, name) in CONTENT_MARKERS.items():
        if key in p or (key.startswith(".") and p.endswith(key)):
            if rx.search(body):
                return True, name
            return False, None
    return None, None  # для этого пути контентного маркера не задано


def classify_open_path(path, status_code, body="", catch_all=False):
    """Классифицировать найденный путь С УЧЁТОМ содержимого (треб. 3).

    path        — относительный путь;
    status_code — HTTP-код;
    body        — тело ответа (для контентной валидации);
    catch_all   — сервер отвечает 200 на любой путь (тогда 200 не значим).

    Возвращает находку либо None.
    """
    p = _norm(path)
    code = status_code or 0

    # security.txt — ожидаемый текстовый файл (RFC 9116). НЕ критично (треб. 3).
    if p == _norm(SECURITY_TXT):
        if code == 200:
            return {
                "severity": "info",
                "category": "secfile_info",
                "title": "Найден security.txt (.well-known/security.txt)",
                "detail": ("Это стандартный текстовый файл с контактами по "
                           "безопасности (RFC 9116), а не админ-панель и не "
                           "утечка. Информационная находка."),
                "recommendation": ("Убедитесь, что в файле указаны актуальные "
                                   "контакты; отдельных действий не требуется."),
                "tool": "curl",
                "severity_reason": ("RFC 9116 предусматривает публичную "
                                    "доступность файла — это норма, уровень info."),
            }
        return None

    # Если catch-all — код 200 ни о чём не говорит, нужен 401/403 (защита) либо
    # подтверждение содержимым; иначе подавляем словарные находки.
    accessible = code in (200, 301, 302, 401, 403)
    if not accessible:
        return None

    # --- Конфигурационные/backup-файлы: critical ТОЛЬКО при подтверждении ---
    if any(p.startswith(_norm(s)) or p == _norm(s) for s in SECRET_FILES):
        confirmed, marker = _content_confirms(path, body)
        if confirmed and code in (200, 301, 302):
            return {
                "severity": "critical",
                "category": "secfile",
                "title": f"Открыт и подтверждён секрет/backup: {path}",
                "detail": (f"Файл {path} доступен (HTTP {code}) и содержит "
                           f"{marker}. Подтверждённая утечка секретов/"
                           f"исходников/дампа БД."),
                "recommendation": ("Немедленно закройте доступ к файлу, удалите "
                                   "его из публичного каталога и смените "
                                   "скомпрометированные секреты."),
                "tool": "curl",
                "severity_reason": ("Содержимое подтверждено маркером "
                                    f"({marker}) — реальная утечка, critical."),
            }
        if code in (401, 403):
            return None  # доступ закрыт — не находка
        if confirmed is False or (confirmed is None and code == 200 and catch_all):
            # 200 без подтверждающего содержимого или catch-all — подавляем.
            return None
        if confirmed is None and code == 200 and not catch_all:
            # Маркер не задан, но файл реально отдаётся вне catch-all —
            # отмечаем как warning (требует ручной проверки), не critical.
            return {
                "severity": "warning",
                "category": "secfile_maybe",
                "title": f"Потенциально доступен служебный файл: {path}",
                "detail": (f"Путь {path} отвечает HTTP 200 (сервер не в режиме "
                           "catch-all), но автоматическое подтверждение "
                           "содержимого не выполнено."),
                "recommendation": "Проверьте файл вручную; при утечке закройте доступ.",
                "tool": "curl",
                "severity_reason": ("Прямого подтверждения содержимым нет — "
                                    "снижено до warning для ручной проверки."),
            }
        return None

    # --- Админ/служебные панели: наличие ≠ компрометация (треб. 3) ---
    if any(p.startswith(_norm(s)) for s in ADMIN_PATHS):
        if catch_all and code == 200:
            return None
        has_login = bool(LOGIN_FORM_RE.search(body or "")) or \
            bool(LOGIN_HINT_RE.search(body or ""))
        if code in (401, 403):
            return {
                "severity": "info",
                "category": "admin_panel",
                "title": f"Служебный путь под защитой авторизации: {path}",
                "detail": f"Путь {path} отвечает HTTP {code} (доступ ограничен).",
                "recommendation": ("Доступ ограничен — убедитесь, что панель не "
                                   "видна из публичного сегмента без VPN."),
                "tool": "curl",
                "severity_reason": ("401/403 означают, что доступ закрыт — это "
                                    "ожидаемо, уровень info."),
            }
        sev = "warning" if has_login else "info"
        return {
            "severity": sev,
            "category": "admin_panel",
            "title": f"Доступна служебная/админская страница: {path}",
            "detail": (f"Путь {path} отвечает HTTP {code}"
                       + (" и содержит форму входа." if has_login
                          else " (форма входа не обнаружена).")),
            "recommendation": ("Ограничьте доступ к панели по IP/VPN, включите "
                               "MFA, вынесите её из публичного периметра."),
            "tool": "curl",
            "severity_reason": (("Обнаружена форма входа — потенциальная точка "
                                 "входа, уровень warning.") if has_login else
                                ("Страница доступна, но без явной формы входа — "
                                 "уровень info, требует проверки.")),
        }

    # --- Тестовые/отладочные разделы ---
    if any(p.startswith(_norm(s)) for s in TEST_PATHS):
        if catch_all and code == 200:
            return None
        # /example, /demo при 404 раньше ошибочно считались отладочными —
        # теперь accessible уже исключил 404. Дополнительно проверяем phpinfo.
        confirmed, marker = _content_confirms(path, body)
        if confirmed is True:
            return {
                "severity": "warning",
                "category": "test_section",
                "title": f"Подтверждён отладочный раздел: {path}",
                "detail": (f"Путь {path} отвечает HTTP {code} и содержит "
                           f"{marker} (например, вывод phpinfo)."),
                "recommendation": "Удалите отладочный раздел с боевого периметра.",
                "tool": "curl",
                "severity_reason": (f"Подтверждено содержимым ({marker}) — "
                                    "реальная утечка конфигурации, warning."),
            }
        if confirmed is False:
            return None
        if code in (401, 403):
            return None
        return {
            "severity": "info",
            "category": "test_section",
            "title": f"Возможный тестовый/отладочный путь: {path}",
            "detail": (f"Путь {path} отвечает HTTP {code}. Содержимое не "
                       "подтверждает раскрытие данных."),
            "recommendation": ("Проверьте назначение раздела; при наличии "
                               "тестовых данных уберите его из периметра."),
            "tool": "curl",
            "severity_reason": ("Доступность без подтверждённого раскрытия "
                                "данных — уровень info."),
        }
    return None


# ----------------------- версии ПО / CMS -----------------------
# Заметка: детальное сопоставление с CVE вынесено в cve_lookup.py (треб. 3б).
# Здесь — лишь грубая отметка устаревшего ПО как контекст (severity warning,
# critical только при явно известном RCE-классе).

OUTDATED_SIGNATURES = (
    (re.compile(r"apache[/ ]2\.4\.(?:49|50)\b", re.I), True,
     "Apache HTTPD 2.4.49/2.4.50 — известный path traversal/RCE "
     "(CVE-2021-41773, CVE-2021-42013)."),
    (re.compile(r"apache[/ ]2\.(?:0|2)\.", re.I), False,
     "Apache HTTPD 2.0/2.2 — снят с поддержки."),
    (re.compile(r"nginx[/ ]1\.(?:[0-9]|1[0-2])\.", re.I), False,
     "Старая ветка nginx (<1.14)."),
    (re.compile(r"php[/ ]5\.", re.I), True,
     "PHP 5.x — снят с поддержки, известны RCE."),
    (re.compile(r"openssh[_/ ]?[1-6]\.", re.I), False,
     "Старая версия OpenSSH — рекомендуется обновление."),
)


def classify_server_version(server_str):
    """Грубая отметка устаревшей версии (контекст к CVE-блоку)."""
    s = server_str or ""
    findings = []
    for rx, is_rce, detail in OUTDATED_SIGNATURES:
        if rx.search(s):
            findings.append({
                "severity": "critical" if is_rce else "warning",
                "category": "outdated",
                "title": f"Устаревшая версия ПО: {s.strip()[:80]}",
                "detail": detail,
                "recommendation": ("Обновите ПО до поддерживаемой версии; "
                                   "примените патчи безопасности."),
                "tool": "whatweb/nmap -sV",
                "severity_reason": (("Версия с публично известным RCE — "
                                     "critical.") if is_rce else
                                    ("Версия снята с поддержки/устарела, "
                                     "явного RCE не зафиксировано — warning.")),
            })
            break
    return findings


def classify_cms(tech_str):
    """Грубая проверка устаревших CMS по фингерпринту whatweb."""
    t = _norm(tech_str)
    findings = []
    m = re.search(r"wordpress[\[ ]?(\d+)\.(\d+)", t)
    if m and int(m.group(1)) < 6:
        findings.append({
            "severity": "warning",
            "category": "outdated_cms",
            "title": f"Устаревшая CMS WordPress {m.group(1)}.{m.group(2)}",
            "detail": "Старые ветки WordPress содержат известные уязвимости "
                      "ядра/плагинов.",
            "recommendation": ("Обновите ядро WordPress и плагины; удалите "
                               "неиспользуемые; включите автообновления."),
            "tool": "whatweb",
            "severity_reason": ("Устаревшая мажорная версия CMS — повышенный "
                                "риск, но без подтверждённого эксплойта "
                                "уровень warning. Точные CVE см. в блоке CVE."),
        })
    return findings


# ----------------------- разбор вывода активных инструментов -----------------------
# Переработано (треб. 3): без наивного keyword-матчинга «xss/rce/sqli», который
# раньше давал ложные critical без деталей. Теперь разбираем СТРУКТУРНЫЕ строки
# конкретных инструментов (nikto OSVDB/CVE, dalfox [POC]).

_NIKTO_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)


def classify_tool_output(tool, output):
    """Разобрать вывод nikto/dalfox в СТРУКТУРНЫЕ находки (без keyword-гадания)."""
    findings = []
    text = output or ""
    if not text.strip():
        return findings

    if tool == "nikto":
        for line in text.splitlines():
            ll = line.strip()
            if not ll.startswith("+"):
                continue
            low = ll.lower()
            cve_m = _NIKTO_CVE_RE.search(ll)
            # Подтверждённые секреты/backup в выводе nikto.
            if any(k in low for k in (".git", ".env", "backup", "sql dump",
                                      "phpinfo")):
                findings.append({
                    "severity": "warning",
                    "category": "nikto_finding",
                    "title": "nikto: потенциальный служебный файл/раздел",
                    "detail": ll[:300],
                    "recommendation": "Проверьте указанный ресурс вручную; "
                                      "при утечке закройте доступ.",
                    "tool": "nikto",
                    "severity_reason": ("nikto указал на потенциальную утечку — "
                                        "warning до ручного подтверждения."),
                })
            elif cve_m:
                findings.append({
                    "severity": "warning",
                    "category": "nikto_cve",
                    "title": f"nikto: упоминание {cve_m.group(1).upper()}",
                    "detail": ll[:300],
                    "recommendation": "Сверьтесь с деталями CVE и обновите ПО.",
                    "tool": "nikto",
                    "cve_id": cve_m.group(1).upper(),
                    "severity_reason": ("Упоминание CVE без подтверждения "
                                        "эксплуатации — warning."),
                })

    elif tool == "dalfox":
        # dalfox печатает подтверждённые находки с тегом [POC]/[VULN].
        for line in text.splitlines():
            low = line.lower()
            if "[poc]" in low or "[vuln]" in low:
                findings.append({
                    "severity": "critical",
                    "category": "xss",
                    "title": "dalfox: подтверждённый XSS (POC)",
                    "detail": line.strip()[:300],
                    "recommendation": ("Экранируйте вывод, внедрите CSP, "
                                       "исправьте уязвимый параметр."),
                    "tool": "dalfox",
                    "severity_reason": ("dalfox подтвердил XSS рабочим POC — "
                                        "critical."),
                })
                break

    elif tool == "wpscan":
        for line in text.splitlines():
            cve_m = _NIKTO_CVE_RE.search(line)
            if cve_m:
                findings.append({
                    "severity": "warning",
                    "category": "wpscan_cve",
                    "title": f"wpscan: {cve_m.group(1).upper()}",
                    "detail": line.strip()[:300],
                    "recommendation": "Обновите ядро/плагины WordPress.",
                    "tool": "wpscan",
                    "cve_id": cve_m.group(1).upper(),
                    "severity_reason": ("wpscan сослался на CVE — warning до "
                                        "подтверждения версии/эксплуатации."),
                })
    return findings


def summarize(findings):
    """Свести список находок к (counts, max_severity)."""
    counts = {"critical": 0, "warning": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    if counts["critical"]:
        return counts, "critical"
    if counts["warning"]:
        return counts, "warning"
    if counts["info"]:
        return counts, "info"
    return counts, None
