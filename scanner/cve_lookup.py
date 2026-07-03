#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_lookup.py — сопоставление обнаруженных версий ПО с известными CVE
(требование 3б v1.4.0).

ТРИ источника, по согласованию с пользователем:

  1. OFFLINE-таблица сигнатур (база модуля) — мгновенно, без сети. Содержит
     наиболее известные критичные CVE для типового периметрового ПО
     (Apache, nginx, OpenSSH, PHP, OpenSSL и т.п.). Используется всегда.

  2. ОНЛАЙН-запрос к CIRCL cve-search (cve.circl.lu) по vendor/product —
     ВКЛЮЧЁН ПО УМОЛЧАНИЮ. Источник доступен напрямую (без VPN,
     без ключа API), агрегирует NVD/CVE 5.x. Запрос выполняется СО
     СТОРОНЫ СКАНЕРА (не через цель), результат кешируется. Любая
     сетевая ошибка/таймаут → graceful degradation (только offline).

  3. nmap NSE vulners — отдельный модуль (scanner вызывает nmap со скриптом
     vulners); здесь только парсинг его текстового/XML-вывода в находки.

ИСТОРИЯ (v1.6.3): онлайн-источник переведён с OSV (api.osv.dev, требовал
выхода через VPN из-за геоблокировок) на CIRCL cve-search, который
открывается напрямую. VPN-обвязка удалена полностью.

ВАЖНО (требование 3): каждая CVE-находка получает АДЕКВАТНЫЙ severity и поле
«Обоснование severity», кликабельные ссылки на NVD и указание источника.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

# Каталог кеша онлайн-ответов (CVE по продукту+версии).
_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "data", "cve_cache")
_CACHE_TTL = 7 * 24 * 3600          # 7 суток
_HTTP_TIMEOUT = 12                   # таймаут одного онлайн-запроса
_USER_AGENT = "NetInvScanner/1.4 (CPT inventory; offline-first CVE)"

NVD_URL = ("https://nvd.nist.gov/vuln/detail/")   # база для кликабельных ссылок
# CIRCL cve-search: поиск по vendor/product, без ключа, отдаёт CVE 5.x JSON.
CIRCL_SEARCH = "https://cve.circl.lu/api/search/"   # + <vendor>/<product>
CIRCL_HEALTH = "https://cve.circl.lu/api/cve/CVE-2021-44228"  # проверка доступности

# Выбор онлайн-источника: "circl" (по умолчанию) или "off" (только offline).


def _cve_source():
    return (os.environ.get("NETINV_CVE_SOURCE") or "circl").strip().lower()


# --- Прокси (требование 5 v1.5.0) --------------------------------------
# Если прямой egress заблокирован, онлайн-запросы можно направить через
# HTTP(S)-прокси (NETINV_HTTPS_PROXY либо штатные HTTPS_PROXY/https_proxy).
# Пример: export NETINV_HTTPS_PROXY=http://127.0.0.1:8080


def _http_proxy():
    """Адрес HTTP(S)-прокси для онлайн-запросов CVE (или None)."""
    return (os.environ.get("NETINV_HTTPS_PROXY")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("https_proxy")
            or None)


def _http_opener():
    """urllib-opener с учётом прокси (если задан) для онлайн-запросов."""
    proxy = _http_proxy()
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()


# Однократная проверка доступности онлайн-источника за процесс (чтобы
# не спамить в лог однотипными ошибками на каждый продукт).
_ONLINE_REACHABLE = None     # None — ещё не проверяли; True/False — результат


def online_healthcheck(log=None, force=False):
    """Однократная проверка доступности онлайн-источника CVE при запуске.

    Выполняется ОДИН раз за процесс (результат кешируется в _ONLINE_REACHABLE),
    чтобы в терминал НЕ сыпались однотипные ошибки на каждый продукт.

    v1.6.3: источник — CIRCL cve-search (cve.circl.lu), доступен напрямую
    без VPN. Возвращает True/False. force=True принудительно перепроверяет.
    """
    global _ONLINE_REACHABLE
    if _ONLINE_REACHABLE is not None and not force:
        return _ONLINE_REACHABLE

    def _log(m):
        if log:
            log("[cve] " + m)

    src = _cve_source()
    if src == "off":
        _ONLINE_REACHABLE = False
        _log("Онлайн-источник CVE отключён (NETINV_CVE_SOURCE=off) — "
             "работает только offline-таблица.")
        return _ONLINE_REACHABLE

    proxy = _http_proxy()
    proxy_note = f" через прокси {proxy}" if proxy else ""
    # Лёгкий GET к известному CVE (Log4Shell) — проверка достижимости хоста.
    req = urllib.request.Request(
        CIRCL_HEALTH, headers={"User-Agent": _USER_AGENT})
    try:
        opener = _http_opener()
        with opener.open(req, timeout=_HTTP_TIMEOUT) as resp:
            _ = resp.status
        _ONLINE_REACHABLE = True
        _log(f"CIRCL cve-search доступен{proxy_note} — онлайн-поиск CVE включён.")
    except urllib.error.HTTPError:
        # Любой HTTP-ответ (даже 4xx) = хост достижим.
        _ONLINE_REACHABLE = True
        _log(f"CIRCL cve-search доступен{proxy_note} — онлайн-поиск CVE включён.")
    except Exception as e:  # noqa: BLE001
        _ONLINE_REACHABLE = False
        _log(f"CIRCL cve-search НЕДОСТУПЕН{proxy_note}: {e}")
        _log("Причина: нет прямого выхода к cve.circl.lu (firewall / периметр). "
             "Онлайн-CVE пропускаются, работает offline-таблица.")
        _log("Решение: задайте прокси export NETINV_HTTPS_PROXY=http://HOST:PORT "
             "(см. README, раздел «Новое в 1.6.3»).")
    return _ONLINE_REACHABLE


def online_teardown(log=None):
    """Завершить фазу онлайн-CVE (v1.6.3).

    Вызывается в finally скана НЕЗАВИСИМО от исхода. VPN больше не используется,
    поэтому здесь только сброс кеша доступности, чтобы следующий скан заново
    перепроверил источник. Никогда не бросает исключений.
    """
    global _ONLINE_REACHABLE
    _ONLINE_REACHABLE = None


# Совместимость со старыми именами (scanner.py мог их вызывать).
osv_healthcheck = online_healthcheck
osv_teardown = online_teardown


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
# 2) ОНЛАЙН-запрос к CIRCL cve-search по vendor/product
#    (кешируемый, graceful degradation)
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


def _clear_cache():
    """Очистить кеш онлайн-ответов (вспомогательно для тестов)."""
    try:
        if os.path.isdir(_CACHE_DIR):
            for fn in os.listdir(_CACHE_DIR):
                if fn.endswith(".json"):
                    os.remove(os.path.join(_CACHE_DIR, fn))
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


# ==========================================================================
# 2a) МАППИНГ баннеров nmap → CIRCL vendor/product (v1.6.3)
# ==========================================================================
# CIRCL cve-search ищет по паре vendor/product (CPE-совместимо). Баннеры nmap
# («Apache httpd», «Golang net/http server», «OpenSSH») — не CPE-имена,
# поэтому нужна таблица сопоставления баннер → (vendor, product, need_ver).
# need_ver=True: без версии CVE-шум слишком велик, поэтому онлайн-запрос без
# версии пропускаем (используется offline-таблица).
#
# ВАЖНО: альтернативы группируем скобками, иначе приоритет | ломает \b-границы
# (например "httpd" без границ матчил бы "lighttpd"). Порядок записей значим:
# сначала более специфичные продукты.
_CIRCL_MAP = [
    # Apache HTTP Server: "Apache", "Apache httpd", "apache2" — но НЕ "lighttpd".
    (re.compile(r"\bapache(?:2)?\b|\bhttpd\b", re.I),
     ("apache", "http_server", True)),
    (re.compile(r"\bnginx\b", re.I),           ("nginx", "nginx", True)),
    # OpenSSH: "OpenSSH" или отдельное слово "ssh". Vendor в CPE — openbsd.
    (re.compile(r"\b(?:openssh|ssh)\b", re.I),  ("openbsd", "openssh", True)),
    (re.compile(r"\bopenssl\b", re.I),         ("openssl", "openssl", True)),
    (re.compile(r"\bcurl\b", re.I),            ("haxx", "curl", True)),
    (re.compile(r"\bsqlite\b", re.I),          ("sqlite", "sqlite", True)),
    (re.compile(r"\bpostgre\w*", re.I),        ("postgresql", "postgresql", True)),
    # Go: стандартная библиотека / net/http.
    (re.compile(r"\bgo(?:lang)?\b|net/http", re.I),
     ("golang", "go", True)),
    (re.compile(r"\bpython\b", re.I),          ("python", "python", True)),
    (re.compile(r"\bproftpd\b", re.I),         ("proftpd", "proftpd", True)),
    (re.compile(r"\bvsftpd\b", re.I),          ("vsftpd", "vsftpd", True)),
    (re.compile(r"\bbind\b|\bnamed\b", re.I),  ("isc", "bind", True)),
    (re.compile(r"\bsamba\b|\bsmbd\b", re.I),  ("samba", "samba", True)),
    (re.compile(r"\bdovecot\b", re.I),         ("dovecot", "dovecot", True)),
    (re.compile(r"\blighttpd\b", re.I),        ("lighttpd", "lighttpd", True)),
    (re.compile(r"\bexim\b", re.I),            ("exim", "exim", True)),
    (re.compile(r"\bpostfix\b", re.I),         ("postfix", "postfix", True)),
]


def map_to_circl(product):
    """Сопоставить баннер продукта с (vendor, product, need_version) по статической таблице.

    Быстрый путь для частых продуктов. Возвращает None, если баннер не
    нашёлся в статической таблице (тогда пробуется динамическое
    разрешение через resolve_vendor_product).
    """
    s = str(product or "").strip().lower()
    if not s:
        return None
    for rx, spec in _CIRCL_MAP:
        if rx.search(s):
            return spec
    return None


# Обратная совместимость: старое имя map_to_osv → map_to_circl.
map_to_osv = map_to_circl


# ==========================================================================
# 2б) ДИНАМИЧЕСКОЕ разрешение vendor/product через CIRCL browse (v1.6.4)
# ==========================================================================
# Статическая таблица покрывает только частые продукты. Для остальных
# баннеров (например «Tandberg-4145 VoIP server») раньше онлайн-запрос
# просто пропускался. Теперь при наличии версии мы пытаемся
# СОПОСТАВИТЬ баннер с реальными vendor/product из каталога CIRCL:
#   * GET /api/browse/            → полный список vendor-слагов (~60тыс, кеш);
#   * GET /api/browse/<vendor>    → список product-слагов этого vendor.
# Токены баннера (без версий и шумовых слов) сверяются с vendor-слагами,
# затем среди product-слагов vendor ищется лучшее совпадение по токенам.

# Шумовые слова в баннерах, которые НЕ являются именем vendor/product.
_BANNER_STOPWORDS = {
    "server", "service", "daemon", "httpd", "voip", "sip", "ftp", "ftpd",
    "smtp", "pop3", "imap", "http", "https", "ssl", "tls", "proxy", "gateway",
    "the", "and", "for", "version", "build", "release", "open", "source",
    "web", "edition", "software", "system", "linux", "unix", "windows",
    "embedded", "appliance", "router", "switch", "firewall", "printer",
}

# Кеш списка vendor-слагов и product-слагов (на время процесса).
_CIRCL_VENDORS = None            # set всех vendor-слагов (или None/ошибка)
_CIRCL_PRODUCTS_CACHE = {}       # vendor → [product-слаги]
CIRCL_BROWSE = "https://cve.circl.lu/api/browse/"   # + [<vendor>]


def _banner_tokens(product):
    """Значимые токены баннера для сопоставления со слагами CIRCL.

    Берём буквенно-цифровые слова длиной ≥ 3, отбрасываем шумовые
    слова и чисто числовые (номера моделей). Порядок сохраняется.
    """
    raw = re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", str(product or ""))
    out = []
    for t in raw:
        tl = t.lower()
        if tl in _BANNER_STOPWORDS or tl.isdigit():
            continue
        # Артефакты версий вида «X14», «v2» — одна буква + только цифры.
        if re.fullmatch(r"[a-z]\d+", tl):
            continue
        if tl not in out:
            out.append(tl)
    return out


def _circl_browse(vendor=None, log=None, detail=None):
    """GET /api/browse[/<vendor>] → список слагов (или [] при ошибке)."""
    url = CIRCL_BROWSE + (urllib.parse.quote(vendor) if vendor else "")
    if detail:
        detail(f"CIRCL browse: GET {url}")
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        opener = _http_opener()
        with opener.open(req, timeout=_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        if log:
            log("[cve] CIRCL browse " + (vendor or "<vendors>")
                + f" недоступен: {e}")
        return []
    # Формат: либо список, либо {"vendors":[...]} / {"product":[...]}.
    if isinstance(data, list):
        return [str(x).lower() for x in data]
    if isinstance(data, dict):
        for key in ("vendor", "vendors", "product", "products"):
            v = data.get(key)
            if isinstance(v, list):
                return [str(x).lower() for x in v]
    return []


def _circl_vendors(log=None, detail=None):
    """Множество всех vendor-слагов CIRCL (кеш на процесс)."""
    global _CIRCL_VENDORS
    if _CIRCL_VENDORS is not None:
        return _CIRCL_VENDORS
    lst = _circl_browse(None, log=log, detail=detail)
    _CIRCL_VENDORS = set(lst) if lst else set()
    if log and _CIRCL_VENDORS:
        log(f"[cve] CIRCL: каталог vendor-слагов загружен — всего "
            f"{len(_CIRCL_VENDORS)}")
    return _CIRCL_VENDORS


def _circl_products(vendor, log=None, detail=None):
    """Список product-слагов для vendor (кеш на процесс)."""
    if vendor in _CIRCL_PRODUCTS_CACHE:
        return _CIRCL_PRODUCTS_CACHE[vendor]
    lst = _circl_browse(vendor, log=log, detail=detail)
    _CIRCL_PRODUCTS_CACHE[vendor] = lst
    return lst


def _best_product(products, tokens):
    """Выбрать лучший product-слаг по совпадению токенов баннера.

    Приоритет: точное равенство токену > слаг содержит токен >
    токен содержит слаг. Если ничего не подходит — None.
    """
    if not products:
        return None
    best, best_score = None, 0
    for slug in products:
        sl = str(slug).lower()
        norm = sl.replace("_", " ").replace("-", " ").split()
        score = 0
        for t in tokens:
            if sl == t:
                score = max(score, 100)
            elif t in norm:
                score = max(score, 80)
            elif t in sl and len(t) >= 4:
                score = max(score, 50)
            elif sl in t and len(sl) >= 4:
                score = max(score, 40)
        if score > best_score:
            best, best_score = sl, score
    return best if best_score >= 40 else None


def resolve_vendor_product(product, log=None, detail=None):
    """Полное разрешение баннера в (vendor, product, need_ver).

    1. Статическая таблица (map_to_circl) — быстрый путь для частых ПО.
    2. Динамическое разрешение через CIRCL browse: токены баннера →
       vendor-слаг → лучший product-слаг. need_ver=True (без версии
       динамический поиск не запускаем — слишком много шума).

    Возвращает (vendor, product, need_ver) или None.
    """
    static = map_to_circl(product)
    if static is not None:
        return static
    # Динамика только при доступности источника (не дёргаем сеть впустую).
    if _ONLINE_REACHABLE is False:
        return None
    tokens = _banner_tokens(product)
    if not tokens:
        return None
    vendors = _circl_vendors(log=log, detail=detail)
    if not vendors:
        return None
    # Ищем vendor-слаг: точное совпадение токену или vendor начинается с него.
    for t in tokens:
        if t in vendors:
            vendor = t
        else:
            cand = [v for v in vendors
                    if v == t or (len(t) >= 4 and v.startswith(t))]
            if not cand:
                continue
            # Короче — ближе к точному vendor.
            vendor = sorted(cand, key=len)[0]
        products = _circl_products(vendor, log=log, detail=detail)
        prod = _best_product(products, tokens)
        if prod is None and vendor in products:
            prod = vendor
        if prod is None and len(products) == 1:
            # У vendor единственный продукт — берём его.
            prod = products[0]
        if prod:
            if log:
                log(f"[cve] CIRCL: баннер «{product}» динамически сопоставлен "
                    f"→ {vendor}/{prod}")
            return (vendor, prod, True)
    return None


# --- Сравнение версий и фильтр «затронута ли версия» ----------------------

# Версия в баннере: «X14.3.6», «2.4.49», «v1.2» — минимум две группы цифр,
# возможный однобуквенный префикс (X/v). Номера моделей вроде
# «Tandberg-4145» (одна группа) не считаются версией.
_BANNER_VER_RE = re.compile(r"\b[Xxvv]?(\d+(?:\.\d+){1,3})\b")


def _version_from_banner(banner):
    """Извлечь версию из текста баннера (если нет отдельного поля).

    Пример: «Tandberg-4145 VoIP server X14.3.6» → '14.3.6'. Берётся
    ПОСЛЕДНее совпадение (версия ПО обычно в конце баннера,
    а номер модели — рядом с именем). Возвращает '' если нет.
    """
    matches = _BANNER_VER_RE.findall(str(banner or ""))
    return matches[-1] if matches else ""


def _version_tuple(v):
    """Числовой кортеж версии для сравнения (напр. '2.4.49' → (2,4,49))."""
    parts = re.findall(r"\d+", str(v or ""))
    return tuple(int(x) for x in parts) if parts else None


def _version_affected(rec, target):
    """Затронута ли target-версия записью CVE 5.x.

    Возвращает True (затронута), False (точно не затронута по указанным
    диапазонам) или None (диапазоны не заданы — неизвестно, оставляем CVE).
    """
    tv = _version_tuple(target)
    if tv is None:
        return None
    cna = (rec.get("containers") or {}).get("cna") or {}
    saw_range = False
    for aff in (cna.get("affected") or []):
        for ver in (aff.get("versions") or []):
            if ver.get("status") != "affected":
                continue
            base = _version_tuple(ver.get("version"))
            lte = _version_tuple(ver.get("lessThanOrEqual"))
            lt = _version_tuple(ver.get("lessThan"))
            if lte or lt:
                saw_range = True
                lo_ok = (base is None) or (base <= tv)
                hi_ok = (tv <= lte) if lte else (tv < lt)
                if lo_ok and hi_ok:
                    return True
            elif base is not None:
                saw_range = True
                if tv == base:
                    return True
    return False if saw_range else None


def _extract_cvss(rec):
    """Извлечь (cvss_балл, severity) из metrics записи CVE 5.x (cna, затем adp)."""
    def scan(cont):
        for m in (cont.get("metrics") or []):
            for k, v in m.items():
                if isinstance(v, dict) and v.get("baseScore") is not None:
                    return (str(v.get("baseScore")),
                            str(v.get("baseSeverity") or "").lower())
        return None
    containers = rec.get("containers") or {}
    got = scan(containers.get("cna") or {})
    if not got:
        for c in (containers.get("adp") or []):
            got = scan(c)
            if got:
                break
    if not got:
        return "", ""
    return got


def _extract_desc(rec):
    """Английское описание CVE из cna.descriptions."""
    cna = (rec.get("containers") or {}).get("cna") or {}
    for de in (cna.get("descriptions") or []):
        if str(de.get("lang", "")).lower().startswith("en"):
            return str(de.get("value") or "")
    descs = cna.get("descriptions") or []
    return str(descs[0].get("value")) if descs else ""


# Максимум CVE-находок на один продукт (самые свежие идут первыми в ответе).
_CIRCL_MAX_FINDINGS = 15


def lookup_circl(product, version, log=None, detail=None):
    """Онлайн-запрос к CIRCL cve-search по vendor/product с фильтром по версии.

    Запрос выполняется СО СТОРОНЫ СКАНЕРА (не через цель). Любая ошибка/таймаут
    → пустой список (graceful degradation). Результат кешируется.

    detail (v1.6.4, Правка 3) — callback детального файл-лога: пишет сырой
    URL запроса, размер ответа и число найденных CVE ТОЛЬКО в файл.
    """
    product = str(product or "").strip()
    version = str(version or "").strip()
    if not product:
        return []
    cached = _cache_get(product, version)
    if cached is not None:
        if detail:
            detail(f"CIRCL: кэш-попадание для «{product}»/«{version or '—'}» "
                   f"→ находок {len(cached)}")
        return cached

    def _log(m):
        if log:
            log("[cve] " + m)
        if detail:
            detail(m)

    # Если однократная проверка показала недоступность — не дёргаем сеть.
    if _ONLINE_REACHABLE is False:
        _cache_put(product, version, [])
        return []

    # v1.6.4: если версия пустая, пробуем извлечь её из баннера
    # (напр. «Tandberg-4145 VoIP server X14.3.6» → 14.3.6).
    if not version:
        vguess = _version_from_banner(product)
        if vguess:
            version = vguess
            _log(f"CIRCL: версия извлечена из баннера «{product}» → {version}")

    # v1.6.4: разрешение через статическую таблицу + динамику (CIRCL browse).
    spec = resolve_vendor_product(product, log=log, detail=detail)
    if spec is None:
        _log(f"CIRCL: продукт «{product}» не сопоставлен с vendor/product "
             f"(ни статически, ни через каталог CIRCL) "
             f"— онлайн-запрос пропущен (используется offline)")
        _cache_put(product, version, [])
        return []
    vendor, prod, need_ver = spec
    if need_ver and not version:
        _log(f"CIRCL: для «{product}» ({vendor}/{prod}) нет версии "
             f"— онлайн-запрос без версии не отправляю (используется offline)")
        _cache_put(product, version, [])
        return []
    _log(f"CIRCL: запрос {vendor}/{prod} (версия цели: {version or '—'})")

    url = (CIRCL_SEARCH + urllib.parse.quote(vendor) + "/"
           + urllib.parse.quote(prod))
    if detail:
        detail(f"CIRCL: GET {url} (User-Agent={_USER_AGENT}, "
               f"timeout={_HTTP_TIMEOUT}s)")
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        opener = _http_opener()
        with opener.open(req, timeout=_HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
        if detail:
            detail(f"CIRCL: ответ получен, размер {len(raw)} байт")
        data = json.loads(raw)
    except urllib.error.HTTPError as e:
        _log(f"CIRCL HTTP {e.code} для {vendor}/{prod} "
             f"— пропускаю (используется offline)")
        _cache_put(product, version, [])
        return []
    except Exception as e:  # noqa: BLE001
        _log(f"CIRCL недоступен для {vendor}/{prod}: {e} (используется offline)")
        _cache_put(product, version, [])
        return []

    # Ответ: {"results": {"nvd": [[cve_id, cve_record_5.x], ...]}, ...}
    results = (data.get("results") or {})
    rows = results.get("nvd") or results.get("cvelistv5") or []
    findings = []
    seen = set()
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        cve_id, rec = row[0], row[1]
        cve = str(cve_id or "").upper()
        if not cve.startswith("CVE-") or cve in seen:
            continue
        if not isinstance(rec, dict):
            continue
        # Фильтр по версии: отбрасываем только те, что ТОЧНО не затронуты.
        if version and _version_affected(rec, version) is False:
            continue
        cvss, sev = _extract_cvss(rec)
        if not sev or sev not in ("critical", "high", "medium", "low"):
            sev = _cvss_to_severity(cvss)
        else:
            sev = {"high": "critical", "medium": "warning",
                   "low": "info", "critical": "critical"}.get(sev, sev)
        seen.add(cve)
        findings.append({
            "cve_id": cve,
            "cvss": cvss,
            "severity": sev,
            "desc": _extract_desc(rec)[:300],
            "source": "circl",
        })
        if len(findings) >= _CIRCL_MAX_FINDINGS:
            break
    if detail:
        detail(f"CIRCL: строк nvd/cvelistv5 в ответе: {len(rows)}, "
               f"отобрано CVE после фильтра версии: {len(findings)}")
    _cache_put(product, version, findings)
    return findings


# Обратная совместимость: старое имя lookup_osv → CIRCL.
lookup_osv = lookup_circl


def lookup_online(product, version, log=None, detail=None):
    """Объединяющий онлайн-поиск (v1.6.3: CIRCL cve-search)."""
    if _cve_source() == "off":
        if detail:
            detail("CIRCL: NETINV_CVE_SOURCE=off — онлайн-поиск отключён")
        return []
    return lookup_circl(product, version, log=log, detail=detail)


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


def collect_cves(product, version, online=True, log=None, detail=None):
    """Собрать CVE из offline-таблицы и (опционально) онлайн-источника.

    Возвращает список находок, дедуплицированных по cve_id (offline имеет
    приоритет описания). Каждая запись пригодна для build_cve_finding().

    detail (v1.6.4, Правка 3) — callback детального файл-лога.
    """
    merged = {}
    off = lookup_offline(product, version)
    for f in off:
        merged[f["cve_id"]] = f
    if detail:
        detail(f"CVE: offline-таблица дала {len(off)} находок "
               f"для «{product}»/«{version or '—'}» (online={online})")
    if online:
        for f in lookup_online(product, version, log=log, detail=detail):
            if f["cve_id"] not in merged:
                merged[f["cve_id"]] = f
    if detail:
        detail(f"CVE: итого после слияния offline+online: {len(merged)}")
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
        "circl": "онлайн-запрос к CIRCL cve-search (cve.circl.lu)",
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
