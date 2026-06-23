#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_lookup.py — сопоставление обнаруженных версий ПО с известными CVE
(требование 3б v1.4.0).

ТРИ источника, по согласованию с пользователем:

  1. OFFLINE-таблица сигнатур (база модуля) — мгновенно, без сети. Содержит
     наиболее известные критичные CVE для типового периметрового ПО
     (Apache, nginx, OpenSSH, PHP, OpenSSL и т.п.). Используется всегда.

  2. ОНЛАЙН-запрос к NVD/OSV по версии ПО — ВКЛЮЧЁН ПО УМОЛЧАНИЮ в основном
     скане. Запрос выполняется СО СТОРОНЫ СКАНЕРА (не через цель), результат
     кешируется. Любая сетевая ошибка/таймаут → graceful degradation
     (используется только offline-таблица).

  3. nmap NSE vulners — отдельный модуль (scanner вызывает nmap со скриптом
     vulners); здесь только парсинг его текстового/XML-вывода в находки.

ВАЖНО (требование 3): каждая CVE-находка получает АДЕКВАТНЫЙ severity и поле
«Обоснование severity», кликабельные ссылки на NVD и указание источника.
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request

# Каталог кеша онлайн-ответов (CVE по продукту+версии).
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "data", "cve_cache")
_CACHE_TTL = 7 * 24 * 3600          # 7 суток
_HTTP_TIMEOUT = 12                   # таймаут одного онлайн-запроса
_USER_AGENT = "NetInvScanner/1.4 (CPT inventory; offline-first CVE)"

NVD_URL = ("https://nvd.nist.gov/vuln/detail/")   # база для кликабельных ссылок
OSV_API = "https://api.osv.dev/v1/query"


# ==========================================================================
# 1) OFFLINE-таблица сигнатур product+version → CVE
# ==========================================================================
# Каждая запись: (regex по строке "product version", список CVE-записей).
# CVE-запись: {"cve": "...", "cvss": "...", "severity": "...", "desc": "..."}.
# Регулярки построены по строке вида "apache 2.4.49" (нижний регистр).
OFFLINE_SIGNATURES = [
    (re.compile(r"apache\b.*\b2\.4\.(?:49)\b"), [
        {"cve": "CVE-2021-41773", "cvss": "7.5", "severity": "critical",
         "desc": "Apache HTTP Server 2.4.49 — path traversal и RCE при "
                 "определённой конфигурации."},
    ]),
    (re.compile(r"apache\b.*\b2\.4\.(?:50)\b"), [
        {"cve": "CVE-2021-42013", "cvss": "9.8", "severity": "critical",
         "desc": "Apache HTTP Server 2.4.50 — неполное исправление 41773, "
                 "path traversal/RCE."},
    ]),
    (re.compile(r"openssh\b.*\b([0-7]\.[0-9])"), [
        {"cve": "CVE-2023-38408", "cvss": "9.8", "severity": "critical",
         "desc": "OpenSSH ssh-agent — потенциальное удалённое выполнение кода "
                 "через PKCS#11 (затронуты версии до 9.3p2)."},
    ]),
    (re.compile(r"openssh\b.*\b([0-6]\.[0-9])"), [
        {"cve": "CVE-2016-0777", "cvss": "6.5", "severity": "warning",
         "desc": "OpenSSH client roaming — утечка приватного ключа "
                 "(до 7.1p2)."},
    ]),
    (re.compile(r"openssl\b.*\b1\.0\.1\b"), [
        {"cve": "CVE-2014-0160", "cvss": "7.5", "severity": "critical",
         "desc": "OpenSSL 1.0.1 — Heartbleed, утечка памяти процесса."},
    ]),
    (re.compile(r"\bphp\b.*\b5\.[0-9]"), [
        {"cve": "CVE-2019-11043", "cvss": "9.8", "severity": "critical",
         "desc": "PHP-FPM — RCE через специально сформированный URL "
                 "(затронуты в т.ч. старые ветки PHP)."},
    ]),
    (re.compile(r"nginx\b.*\b1\.(?:[0-9]|1[0-2])\.[0-9]"), [
        {"cve": "CVE-2019-20372", "cvss": "5.3", "severity": "warning",
         "desc": "nginx <1.17.7 — обход ограничений через error_page "
                 "request smuggling."},
    ]),
    (re.compile(r"(?:proftpd)\b.*\b1\.3\.5\b"), [
        {"cve": "CVE-2015-3306", "cvss": "10.0", "severity": "critical",
         "desc": "ProFTPD 1.3.5 — mod_copy позволяет неаутентифицированную "
                 "запись/чтение файлов (RCE)."},
    ]),
    (re.compile(r"(?:vsftpd)\b.*\b2\.3\.4\b"), [
        {"cve": "CVE-2011-2523", "cvss": "9.8", "severity": "critical",
         "desc": "vsftpd 2.3.4 — бэкдор, открывающий командную оболочку."},
    ]),
]


def _normalize(product, version):
    """Собрать нормализованную строку 'product version' в нижнем регистре."""
    parts = [str(product or "").strip(), str(version or "").strip()]
    return re.sub(r"\s+", " ", " ".join(p for p in parts if p)).lower()


def lookup_offline(product, version):
    """Поиск CVE в offline-таблице по product+version.

    Возвращает список находок (dict: cve_id/cvss/severity/desc/source).
    """
    s = _normalize(product, version)
    if not s:
        return []
    out = []
    for rx, cves in OFFLINE_SIGNATURES:
        if rx.search(s):
            for c in cves:
                out.append({
                    "cve_id": c["cve"],
                    "cvss": c["cvss"],
                    "severity": c["severity"],
                    "desc": c["desc"],
                    "source": "offline",
                })
    return out


# ==========================================================================
# 2) ОНЛАЙН-запрос к OSV/NVD по версии (кешируемый, graceful degradation)
# ==========================================================================

def _cache_path(product, version):
    key = _normalize(product, version).replace(" ", "_").replace("/", "_")
    key = re.sub(r"[^a-z0-9_.\-]", "", key) or "unknown"
    return os.path.join(_CACHE_DIR, key + ".json")


def _cache_get(product, version):
    path = _cache_path(product, version)
    try:
        if os.path.isfile(path) and (time.time() - os.path.getmtime(path)) < _CACHE_TTL:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:  # noqa: BLE001
        return None
    return None


def _cache_put(product, version, data):
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        with open(_cache_path(product, version), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        pass


def _cvss_to_severity(score):
    """CVSS-балл → severity для отображения (треб. 3: адекватный уровень)."""
    try:
        v = float(score)
    except (TypeError, ValueError):
        return "info"
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "critical"
    if v >= 4.0:
        return "warning"
    return "info"


def lookup_osv(product, version, log=None):
    """Онлайн-запрос к OSV (api.osv.dev) по продукту+версии.

    Запрос выполняется СО СТОРОНЫ СКАНЕРА (не через цель). Любая ошибка/таймаут
    → возвращается пустой список (graceful degradation). Результат кешируется.
    """
    if not product:
        return []
    cached = _cache_get(product, version)
    if cached is not None:
        return cached

    def _log(m):
        if log:
            log("[cve] " + m)

    findings = []
    # OSV принимает package.name + version; для нативного ПО точное сопоставление
    # ограничено, поэтому используем эвристический запрос по имени продукта.
    payload = json.dumps({
        "version": str(version or ""),
        "package": {"name": str(product).lower()},
    }).encode("utf-8")
    req = urllib.request.Request(
        OSV_API, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        _log(f"OSV недоступен для {product} {version}: {e} (используется offline)")
        _cache_put(product, version, [])      # кешируем «пусто», чтобы не долбить сеть
        return []

    for vuln in (data.get("vulns") or [])[:10]:
        cve_id = vuln.get("id", "")
        # Пытаемся выбрать CVE-алиас, если id не CVE-формата.
        aliases = vuln.get("aliases") or []
        cve = next((a for a in [cve_id] + aliases if str(a).startswith("CVE-")),
                   cve_id)
        cvss = ""
        sev = "info"
        for s in (vuln.get("severity") or []):
            sc = s.get("score", "")
            m = re.search(r"(\d+\.\d+)", str(sc))
            if m:
                cvss = m.group(1)
                sev = _cvss_to_severity(cvss)
                break
        findings.append({
            "cve_id": cve,
            "cvss": cvss,
            "severity": sev,
            "desc": (vuln.get("summary") or vuln.get("details") or "")[:300],
            "source": "osv",
        })
    _cache_put(product, version, findings)
    return findings


def lookup_online(product, version, log=None):
    """Объединяющий онлайн-поиск (сейчас OSV; NVD — через ссылку на детали)."""
    return lookup_osv(product, version, log=log)


# ==========================================================================
# 3) Парсинг вывода nmap NSE vulners
# ==========================================================================
# vulners выводит блок вида:
#   | vulners:
#   |   cpe:/a:apache:http_server:2.4.49:
#   |       CVE-2021-41773   7.5    https://vulners.com/cve/CVE-2021-41773
_VULNERS_LINE = re.compile(
    r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d+)", re.IGNORECASE)


def parse_vulners_output(output):
    """Разобрать текстовый вывод nmap --script vulners в список CVE-находок."""
    findings = []
    seen = set()
    for line in (output or "").splitlines():
        m = _VULNERS_LINE.search(line)
        if not m:
            continue
        cve = m.group(1).upper()
        if cve in seen:
            continue
        seen.add(cve)
        cvss = m.group(2)
        findings.append({
            "cve_id": cve,
            "cvss": cvss,
            "severity": _cvss_to_severity(cvss),
            "desc": "Сопоставление версии ПО с CVE по базе vulners (nmap NSE).",
            "source": "vulners",
        })
    return findings


# ==========================================================================
# Объединение и формирование находок для db.add_vuln
# ==========================================================================

def nvd_link(cve_id):
    """Кликабельная ссылка на детальную страницу CVE в NVD."""
    cid = str(cve_id or "").strip()
    if not cid:
        return ""
    return NVD_URL + urllib.parse.quote(cid)


def collect_cves(product, version, online=True, log=None):
    """Собрать CVE из offline-таблицы и (опционально) онлайн-источника.

    Возвращает список находок, дедуплицированных по cve_id (offline имеет
    приоритет описания). Каждая запись пригодна для build_cve_finding().
    """
    merged = {}
    for f in lookup_offline(product, version):
        merged[f["cve_id"]] = f
    if online:
        for f in lookup_online(product, version, log=log):
            if f["cve_id"] not in merged:
                merged[f["cve_id"]] = f
    return list(merged.values())


def build_cve_finding(product, version, url, cve, port=None):
    """Преобразовать CVE-запись в находку для db.add_vuln (с обоснованием).

    severity_reason (треб. 3) объясняет, почему выбран этот уровень: исходя из
    CVSS-балла и источника сопоставления.
    """
    cvss = cve.get("cvss", "")
    sev = cve.get("severity") or _cvss_to_severity(cvss)
    src_label = {
        "offline": "offline-таблица сигнатур NetInv",
        "osv": "онлайн-запрос к OSV (api.osv.dev)",
        "nvd": "онлайн-запрос к NVD",
        "vulners": "nmap NSE vulners",
    }.get(cve.get("source"), cve.get("source", ""))

    reason_parts = []
    if cvss:
        reason_parts.append(f"CVSS {cvss}")
    reason_parts.append(f"источник: {src_label}")
    if sev == "critical":
        reason_parts.append("высокий балл CVSS (≥7.0) — критично")
    elif sev == "warning":
        reason_parts.append("средний балл CVSS (4.0–6.9) — предупреждение")
    else:
        reason_parts.append("низкий балл/без оценки — информационно")

    sw = (str(product or "") + " " + str(version or "")).strip() or "ПО"
    detail = (f"Версия ПО «{sw}» сопоставлена с {cve['cve_id']}"
              + (f" (CVSS {cvss})" if cvss else "") + ". "
              + (cve.get("desc") or ""))
    return {
        "severity": sev,
        "category": "cve",
        "title": f"{cve['cve_id']}: уязвимость в {sw}",
        "detail": detail.strip(),
        "recommendation": ("Обновите ПО до версии с исправлением; сверьтесь с "
                           f"деталями CVE: {nvd_link(cve['cve_id'])}"),
        "tool": src_label,
        "severity_reason": "; ".join(reason_parts),
        "cve_id": cve["cve_id"],
        "cvss": cvss,
        "cve_source": cve.get("source", ""),
        "url": url or "",
    }


if __name__ == "__main__":
    import sys
    prod = sys.argv[1] if len(sys.argv) > 1 else "apache"
    ver = sys.argv[2] if len(sys.argv) > 2 else "2.4.49"
    for f in collect_cves(prod, ver, online=False):
        print(build_cve_finding(prod, ver, "http://example/", f))
