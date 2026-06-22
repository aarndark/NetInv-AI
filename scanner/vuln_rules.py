#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_rules.py — классификатор находок web-уязвимостей (требование 5).

Модуль НЕ запускает инструменты — он принимает «сырые» наблюдения, собранные
webscan.py (заголовки HTTP, найденные пути, версии серверов/CMS, вывод
nikto/whatweb/wpscan/dalfox/nmap-http), и превращает их в структурированные
находки с уровнем критичности и авто-рекомендацией.

Уровни критичности (severity):
  critical — требует МАКСИМАЛЬНО оперативного реагирования (красная подсветка):
             * открытые служебные/админские панели и тестовые разделы;
             * устаревшие веб-серверы/CMS/плагины с известными RCE/SQLi/XSS;
             * открытые конфигурационные/backup-файлы (.git, .env, backup.sql);
             * подтверждённые XSS (dalfox) / SQLi / RCE.
  warning  — жёлтая подсветка:
             * отсутствие/неправильная настройка security-headers
               (HSTS, X-Frame-Options, CSP, X-Content-Type-Options);
             * устаревшие версии без явного признака RCE/SQLi/XSS.
  info     — прочие наблюдения (серая подсветка).

Все проверки неинтрузивны по умолчанию (см. webscan.py). Здесь — только разбор.
"""

import re

# ----------------------- наборы признаков -----------------------

# Обязательные security-headers и человекочитаемые названия (требование 5).
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (Strict-Transport-Security)",
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy (CSP)",
    "x-content-type-options": "X-Content-Type-Options",
}

# Чувствительные служебные/админские/тестовые пути (открытость = critical).
ADMIN_PATHS = (
    "/admin", "/administrator", "/wp-admin/", "/phpmyadmin/", "/manager/html",
    "/login", "/user/login", "/admin/login", "/cpanel", "/webmail",
    "/console", "/jenkins", "/grafana", "/kibana", "/_cat", "/actuator",
    "/server-status", "/server-info", "/.well-known/security.txt",
)
TEST_PATHS = (
    "/test", "/test.php", "/dev", "/staging", "/debug", "/phpinfo.php",
    "/info.php", "/example", "/demo", "/backup", "/old", "/tmp",
)

# Открытые конфигурационные/backup-файлы (открытость = critical).
SECRET_FILES = (
    "/.git/config", "/.git/HEAD", "/.env", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/wp-config.php.bak", "/config.php.bak",
    "/.htpasswd", "/.svn/entries", "/web.config.bak", "/backup.zip",
    "/backup.tar.gz", "/.DS_Store",
)

# Ключевые слова из вывода nikto/nmap, указывающие на RCE/SQLi/XSS.
RCE_KEYWORDS = ("rce", "remote code execution", "command injection",
                "shellshock", "deserialization")
SQLI_KEYWORDS = ("sql injection", "sqli", "error-based sql")
XSS_KEYWORDS = ("xss", "cross-site scripting", "reflected xss")


def _norm(s):
    return (s or "").strip().lower()


# ----------------------- отдельные правила -----------------------

def classify_security_headers(present_headers, is_https=True):
    """Найти отсутствующие security-headers. present_headers — множество имён
    заголовков в нижнем регистре. Возвращает список находок (severity=warning).
    """
    findings = []
    present = {_norm(h) for h in (present_headers or [])}
    for key, label in SECURITY_HEADERS.items():
        # HSTS актуален только для HTTPS.
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
            })
    return findings


def _header_recommendation(key):
    rec = {
        "strict-transport-security":
            "Включите HSTS: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload.",
        "x-frame-options":
            "Добавьте X-Frame-Options: DENY (или SAMEORIGIN) для защиты от "
            "clickjacking.",
        "content-security-policy":
            "Настройте Content-Security-Policy, ограничив источники скриптов/"
            "стилей и запретив inline-скрипты.",
        "x-content-type-options":
            "Добавьте X-Content-Type-Options: nosniff, чтобы запретить MIME-"
            "sniffing.",
    }
    return rec.get(key, "")


def classify_open_path(path, status_code):
    """Классифицировать найденный доступный путь. Возвращает находку либо None.
    path — относительный путь; status_code — HTTP-код (200/401/403/...).
    """
    p = _norm(path)
    accessible = status_code in (200, 301, 302, 401, 403)
    if not accessible:
        return None
    # Открытые конфигурационные/backup-файлы — критично при 200/301/302.
    if any(p.startswith(_norm(s)) or p == _norm(s) for s in SECRET_FILES):
        if status_code in (200, 301, 302):
            return {
                "severity": "critical",
                "category": "secfile",
                "title": f"Открыт конфигурационный/backup-файл: {path}",
                "detail": f"Файл {path} доступен (HTTP {status_code}). "
                          "Возможна утечка секретов/исходников/дампа БД.",
                "recommendation":
                    "Немедленно закройте доступ к файлу на уровне веб-сервера "
                    "и удалите его из публичного каталога; смените "
                    "скомпрометированные секреты.",
                "tool": "curl",
            }
        return None
    # Админ/служебные панели.
    if any(p.startswith(_norm(s)) for s in ADMIN_PATHS):
        sev = "critical"
        return {
            "severity": sev,
            "category": "admin_panel",
            "title": f"Доступна служебная/админская панель: {path}",
            "detail": f"Путь {path} отвечает (HTTP {status_code}).",
            "recommendation":
                "Ограничьте доступ к панели по IP/VPN, включите MFA и "
                "вынесите её из публичного периметра.",
            "tool": "curl",
        }
    # Тестовые/отладочные разделы.
    if any(p.startswith(_norm(s)) for s in TEST_PATHS):
        return {
            "severity": "critical",
            "category": "test_section",
            "title": f"Доступен тестовый/отладочный раздел: {path}",
            "detail": f"Путь {path} отвечает (HTTP {status_code}). "
                      "Тестовые разделы часто раскрывают конфигурацию/данные.",
            "recommendation":
                "Удалите тестовые/отладочные разделы с боевого периметра "
                "или закройте доступ к ним.",
            "tool": "curl",
        }
    return None


# Сигнатуры устаревших версий с известными классами уязвимостей.
# (product_regex, версия «до которой устарело», класс уязвимости)
OUTDATED_SIGNATURES = (
    # Apache 2.4.49/2.4.50 — CVE-2021-41773 / CVE-2021-42013 (path traversal → RCE).
    (re.compile(r"apache[/ ]2\.4\.(?:49|50)\b", re.I), "RCE/path traversal",
     "Apache HTTPD 2.4.49/2.4.50 — известный path traversal/RCE "
     "(CVE-2021-41773, CVE-2021-42013)."),
    (re.compile(r"apache[/ ]2\.(?:0|2)\.", re.I), "RCE/прочие",
     "Apache HTTPD 2.0/2.2 — снят с поддержки, известны RCE/обходы."),
    (re.compile(r"nginx[/ ]1\.(?:[0-9]|1[0-2])\.", re.I), "RCE/прочие",
     "Старая ветка nginx (<1.14) — известны уязвимости, в т.ч. RCE."),
    (re.compile(r"php[/ ]5\.", re.I), "RCE/прочие",
     "PHP 5.x — снят с поддержки, многочисленные RCE/обходы."),
    (re.compile(r"openssh[_/ ]?[1-6]\.", re.I), "прочие",
     "Старая версия OpenSSH — рекомендуется обновление."),
)


def classify_server_version(server_str):
    """Разобрать заголовок Server/баннер на предмет устаревшей версии."""
    s = server_str or ""
    findings = []
    for rx, vclass, detail in OUTDATED_SIGNATURES:
        if rx.search(s):
            rce = "RCE" in vclass
            findings.append({
                "severity": "critical" if rce else "warning",
                "category": "outdated",
                "title": f"Устаревшая версия ПО: {s.strip()[:80]}",
                "detail": detail + (" Класс: " + vclass if vclass else ""),
                "recommendation":
                    "Обновите ПО до поддерживаемой версии; примените патчи "
                    "безопасности и проверьте конфигурацию.",
                "tool": "whatweb",
            })
            break
    return findings


def classify_cms(tech_str):
    """Грубая проверка устаревших CMS/плагинов по фингерпринту whatweb."""
    t = _norm(tech_str)
    findings = []
    # WordPress с указанием старой мажорной версии.
    m = re.search(r"wordpress[\[ ]?(\d+)\.(\d+)", t)
    if m:
        major = int(m.group(1))
        if major < 6:
            findings.append({
                "severity": "critical",
                "category": "outdated_cms",
                "title": f"Устаревшая CMS WordPress {m.group(1)}.{m.group(2)}",
                "detail": "Старые ветки WordPress содержат известные RCE/SQLi/"
                          "XSS (в т.ч. в плагинах).",
                "recommendation":
                    "Обновите ядро WordPress и все плагины; удалите "
                    "неиспользуемые плагины/темы; включите автообновления.",
                "tool": "whatweb",
            })
    return findings


def classify_tool_output(tool, output):
    """Разобрать текстовый вывод nikto/nmap-http/wpscan на ключевые слова
    RCE/SQLi/XSS и явные находки. Возвращает список находок.
    """
    o = _norm(output)
    findings = []
    if not o:
        return findings

    def _add(sev, cat, title, detail, rec):
        findings.append({"severity": sev, "category": cat, "title": title,
                         "detail": detail, "recommendation": rec, "tool": tool})

    if any(k in o for k in RCE_KEYWORDS):
        _add("critical", "rce", f"Признаки RCE ({tool})",
             "В выводе инструмента найдены признаки удалённого выполнения кода.",
             "Срочно изолируйте узел, проверьте логи на эксплуатацию, "
             "обновите уязвимый компонент.")
    if any(k in o for k in SQLI_KEYWORDS):
        _add("critical", "sqli", f"Признаки SQL-инъекции ({tool})",
             "В выводе инструмента найдены признаки SQLi.",
             "Параметризуйте запросы, обновите компонент, проверьте логи БД.")
    if any(k in o for k in XSS_KEYWORDS):
        _add("critical", "xss", f"Признаки XSS ({tool})",
             "В выводе инструмента найдены признаки межсайтового скриптинга.",
             "Экранируйте вывод, внедрите CSP, обновите уязвимый компонент.")

    # nikto часто прямо сообщает об интересных файлах/директориях.
    if tool == "nikto":
        for line in (output or "").splitlines():
            ll = _norm(line)
            if ".git" in ll or ".env" in ll or "backup" in ll:
                _add("critical", "secfile",
                     "nikto: найден потенциально открытый секрет/backup",
                     line.strip()[:300],
                     "Закройте доступ к файлу и смените секреты.")
                break
    return findings


def summarize(findings):
    """Свести список находок к (counts, max_severity).
    counts — {critical, warning, info}; max_severity — самый высокий уровень.
    """
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
