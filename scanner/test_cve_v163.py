#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты v1.6.3: онлайн-источник CVE — CIRCL cve-search (cve.circl.lu).

Проверяется:
  1. Маппинг баннеров nmap → (vendor, product, need_ver) для CIRCL.
  2. Отсечка заведомо бесполезных запросов (нет маппинга / нет версии) —
     сетевой вызов НЕ уходит.
  3. Парсинг реального CIRCL-ответа (results.nvd) в находки cve_id/cvss/…
  4. Фильтр по версии _version_affected (True/False/None по CVE 5.x).
  5. Извлечение CVSS/описания из CVE 5.x (_extract_cvss, _extract_desc).
  6. Graceful degradation: _ONLINE_REACHABLE=False → [] без сети.
  7. Источник «off» (NETINV_CVE_SOURCE=off) → онлайн отключён.
  8. teardown идемпотентен, VPN-обвязки больше нет.

Запуск:  .venv/bin/python scanner/test_cve_v163.py
Тесты автономны: сеть НЕ дёргается (перехватываем opener). Проверяется
именно логика, а не внешняя доступность CIRCL.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cve_lookup as c

_failures = []

# Изолируем файловый кеш от боевого: каждый тест чистит временную папку.
_TMP_CACHE = tempfile.mkdtemp(prefix="netinv_cve_test_")
c._CACHE_DIR = _TMP_CACHE


def _clear_cache():
    for fn in os.listdir(_TMP_CACHE):
        try:
            os.remove(os.path.join(_TMP_CACHE, fn))
        except OSError:
            pass


def check(name, cond, detail=""):
    mark = "OK " if cond else "FAIL"
    if not cond:
        _failures.append(name + (f" — {detail}" if detail else ""))
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


# --- Фикстура: упрощённый CIRCL-ответ по apache/http_server ----------------
# Формат подтверждён вручную: {"results": {"nvd": [[cve_id, cve_5.x], ...]}}.
def _rec(cve_id, base_score, severity, desc, versions=None):
    """Собрать минимальную запись CVE 5.x с metrics/affected/descriptions."""
    cna = {
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": [{"cvssV3_1": {"baseScore": base_score,
                                  "baseSeverity": severity}}],
    }
    if versions is not None:
        cna["affected"] = [{"versions": versions}]
    return {"cveMetadata": {"cveId": cve_id},
            "containers": {"cna": cna}}


_CIRCL_APACHE = {
    "results": {
        "nvd": [
            # затронуты 2.4.0 .. 2.4.49 включительно (CVE-2021-41773)
            ["CVE-2021-41773", _rec(
                "CVE-2021-41773", 7.5, "HIGH",
                "Path traversal in Apache HTTP Server 2.4.49.",
                [{"version": "2.4.0", "lessThanOrEqual": "2.4.49",
                  "status": "affected"}])],
            # затронута только 2.4.50 (CVE-2021-42013) — 2.4.49 НЕ входит
            ["CVE-2021-42013", _rec(
                "CVE-2021-42013", 9.8, "CRITICAL",
                "RCE in Apache HTTP Server 2.4.50.",
                [{"version": "2.4.50", "status": "affected"}])],
            # без диапазонов версий — оставляем всегда (severity MEDIUM)
            ["CVE-2020-11985", _rec(
                "CVE-2020-11985", 5.3, "MEDIUM",
                "IP spoofing related issue.")],
        ],
        "cvelistv5": [],
    },
    "total_count": 3,
}


class _StubOpener:
    """Опенер, отдающий заранее заданный JSON без реальной сети."""
    def __init__(self, response_obj):
        self.calls = 0
        self._resp = json.dumps(response_obj).encode("utf-8")

    def open(self, req, timeout=None):
        self.calls += 1
        outer = self

        class _R:
            status = 200

            def read(self_inner):
                return outer._resp

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False
        return _R()


class _SentinelOpener:
    """«Взрывается» при любом сетевом вызове — доказывает отсутствие запроса."""
    def __init__(self):
        self.calls = 0

    def open(self, *a, **k):
        self.calls += 1
        raise AssertionError("СЕТЕВОЙ ЗАПРОС НЕ ДОЛЖЕН БЫЛ УЙТИ")


# --- 1. Таблица маппинга map_to_circl -------------------------------------
def test_mapping():
    cases = {
        "Apache httpd": ("apache", "http_server", True),
        "Apache httpd 2.4.49": ("apache", "http_server", True),
        "apache2": ("apache", "http_server", True),
        "nginx": ("nginx", "nginx", True),
        "OpenSSH": ("openbsd", "openssh", True),
        "OpenSSH 8.2p1": ("openbsd", "openssh", True),
        "ssh": ("openbsd", "openssh", True),
        "openssl": ("openssl", "openssl", True),
        "PostgreSQL": ("postgresql", "postgresql", True),
        "Golang net/http server": ("golang", "go", True),
        "Python": ("python", "python", True),
        "vsftpd": ("vsftpd", "vsftpd", True),
        "ProFTPD": ("proftpd", "proftpd", True),
    }
    for product, expected in cases.items():
        got = c.map_to_circl(product)
        check(f"map «{product}» → {expected}", got == expected,
              f"получено {got}")

    # «lighttpd» не должен матчиться на apache/httpd.
    got = c.map_to_circl("lighttpd 1.4.55")
    check("map «lighttpd» → lighttpd (не apache)",
          got == ("lighttpd", "lighttpd", True), f"получено {got}")

    # Продукты БЕЗ сопоставления → None (онлайн-запрос не шлём).
    for product in ["Cisco Expressway E", "Microsoft IIS",
                    "unknown-daemon", "", None]:
        got = c.map_to_circl(product)
        check(f"map «{product}» → None", got is None, f"получено {got}")

    # Обратная совместимость: старое имя.
    check("alias map_to_osv == map_to_circl",
          c.map_to_osv is c.map_to_circl)


# --- 2. Отсечка: без версии / без маппинга запрос НЕ уходит ----------------
# ПРИМЕЧАНИЕ v1.6.4: при отсутствии статического маппинга теперь запускается
# динамическое разрешение через каталог CIRCL (/api/browse). Поэтому сетевой
# вызов к КАТАЛОГУ допустим, но запрос к /api/search уходить НЕ должен, если
# продукт так и не сопоставлен или нет версии. Проверяем именно search.
class _NoSearchOpener:
    """Отдаёт каталог browse БЕЗ нужного vendor; на /api/search — «взрыв»."""
    def __init__(self, vendors=None):
        self.calls = 0
        self.search_calls = 0
        self._vendors = vendors if vendors is not None else ["apache", "nginx"]

    def open(self, req, timeout=None):
        self.calls += 1
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "/api/search/" in url:
            self.search_calls += 1
            raise AssertionError("ЗАПРОС /api/search НЕ ДОЛЖЕН БЫЛ УЙТИ")
        # browse: список vendor-слагов / product-слагов.
        body = json.dumps(self._vendors).encode("utf-8")

        class _R:
            status = 200

            def read(self_inner):
                return body

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False
        return _R()


def test_skip_without_request():
    c._CIRCL_VENDORS = None            # сброс процессного кеша каталога
    c._CIRCL_PRODUCTS_CACHE = {}
    opener = _NoSearchOpener(vendors=["apache", "nginx"])
    c._http_opener = lambda: opener
    c._ONLINE_REACHABLE = True   # источник «достижим»
    _clear_cache()

    # a) Нет сопоставления (ни статики, ни в каталоге) → запрос /search не уходит.
    r = c.lookup_circl("Zzzunknown Daemon", "1.2.3")
    check("нет маппинга → [] и без запроса /search",
          r == [] and opener.search_calls == 0,
          f"r={r}, search_calls={opener.search_calls}")

    # b) Есть статический маппинг, но нет версии (need_ver=True) → /search не уходит.
    _clear_cache()
    opener2 = _NoSearchOpener()
    c._http_opener = lambda: opener2
    r = c.lookup_circl("Apache httpd", "")
    check("маппинг без версии → [] и без запроса /search",
          r == [] and opener2.search_calls == 0,
          f"r={r}, search_calls={opener2.search_calls}")


# --- 3. Парсинг реального CIRCL-ответа + фильтр по версии ------------------
def test_parse_and_version_filter():
    opener = _StubOpener(_CIRCL_APACHE)
    c._http_opener = lambda: opener
    c._ONLINE_REACHABLE = True
    _clear_cache()

    r = c.lookup_circl("Apache httpd", "2.4.49")
    ids = {f["cve_id"] for f in r}
    check("сетевой запрос отправлен (calls==1)", opener.calls == 1,
          f"calls={opener.calls}")
    # 2.4.49 входит в 41773; НЕ входит в 42013 (только 2.4.50) → отсечь;
    # 11985 без диапазонов → оставить (None).
    check("CVE-2021-41773 включён (версия затронута)",
          "CVE-2021-41773" in ids, f"ids={ids}")
    check("CVE-2021-42013 отсечён (2.4.49 не затронута)",
          "CVE-2021-42013" not in ids, f"ids={ids}")
    check("CVE-2020-11985 включён (диапазон не задан → None)",
          "CVE-2020-11985" in ids, f"ids={ids}")

    # severity mapping: HIGH→critical, CRITICAL→critical, MEDIUM→warning.
    by_id = {f["cve_id"]: f for f in r}
    check("CVE-2021-41773 severity=critical (HIGH)",
          by_id.get("CVE-2021-41773", {}).get("severity") == "critical",
          f"{by_id.get('CVE-2021-41773')}")
    check("CVE-2020-11985 severity=warning (MEDIUM)",
          by_id.get("CVE-2020-11985", {}).get("severity") == "warning",
          f"{by_id.get('CVE-2020-11985')}")
    check("cvss извлечён из metrics",
          by_id.get("CVE-2021-41773", {}).get("cvss") == "7.5",
          f"{by_id.get('CVE-2021-41773')}")
    check("source=circl проставлен",
          all(f["source"] == "circl" for f in r), f"r={r}")
    check("desc извлечён (en)",
          "Path traversal" in by_id.get("CVE-2021-41773", {}).get("desc", ""),
          f"{by_id.get('CVE-2021-41773')}")

    # Повторный вызов — из кеша, без новой сети.
    calls_before = opener.calls
    r2 = c.lookup_circl("Apache httpd", "2.4.49")
    check("повторный вызов из кеша (без сети)",
          opener.calls == calls_before and r2 == r,
          f"calls={opener.calls}")


# --- 4. _version_affected: логика диапазонов CVE 5.x ----------------------
def test_version_affected():
    rec_range = _rec("X", 7.5, "HIGH", "d",
                     [{"version": "2.4.0", "lessThanOrEqual": "2.4.49",
                       "status": "affected"}])
    rec_lt = _rec("X", 7.5, "HIGH", "d",
                  [{"version": "1.0", "lessThan": "1.5",
                    "status": "affected"}])
    rec_exact = _rec("X", 7.5, "HIGH", "d",
                     [{"version": "2.4.50", "status": "affected"}])
    rec_none = _rec("X", 7.5, "HIGH", "d")   # без affected

    check("диапазон lessThanOrEqual: 2.4.49 → True",
          c._version_affected(rec_range, "2.4.49") is True)
    check("диапазон lessThanOrEqual: 2.4.50 → False",
          c._version_affected(rec_range, "2.4.50") is False)
    check("диапазон lessThan: 1.4 → True",
          c._version_affected(rec_lt, "1.4") is True)
    check("диапазон lessThan: 1.5 → False (строго <)",
          c._version_affected(rec_lt, "1.5") is False)
    check("точная версия 2.4.50 → True",
          c._version_affected(rec_exact, "2.4.50") is True)
    check("точная версия 2.4.49 против exact 2.4.50 → False",
          c._version_affected(rec_exact, "2.4.49") is False)
    check("нет affected → None (неизвестно)",
          c._version_affected(rec_none, "2.4.49") is None)
    check("нет target-версии → None",
          c._version_affected(rec_range, "") is None)


# --- 5. _extract_cvss / _extract_desc: cna и adp fallback -----------------
def test_extract_helpers():
    # CVSS из cna.
    rec_cna = _rec("X", 9.8, "CRITICAL", "boom")
    cvss, sev = c._extract_cvss(rec_cna)
    check("_extract_cvss из cna", cvss == "9.8" and sev == "critical",
          f"({cvss},{sev})")

    # CVSS из adp (cna без metrics).
    rec_adp = {"containers": {
        "cna": {"descriptions": [{"lang": "en", "value": "x"}]},
        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 4.3,
                                           "baseSeverity": "MEDIUM"}}]}],
    }}
    cvss, sev = c._extract_cvss(rec_adp)
    check("_extract_cvss из adp fallback",
          cvss == "4.3" and sev == "medium", f"({cvss},{sev})")

    # Нет metrics вовсе → ("","").
    rec_empty = {"containers": {"cna": {}}}
    check("_extract_cvss без metrics → пусто",
          c._extract_cvss(rec_empty) == ("", ""))

    # Описание: предпочтение en.
    rec_desc = {"containers": {"cna": {"descriptions": [
        {"lang": "es", "value": "hola"},
        {"lang": "en", "value": "hello"}]}}}
    check("_extract_desc берёт en",
          c._extract_desc(rec_desc) == "hello")
    check("_extract_desc пусто без descriptions",
          c._extract_desc({"containers": {"cna": {}}}) == "")


# --- 6. Graceful degradation: источник недоступен → [] без сети -----------
def test_graceful_degradation():
    c._ONLINE_REACHABLE = False
    opener = _SentinelOpener()
    c._http_opener = lambda: opener
    _clear_cache()
    r = c.lookup_circl("nginx", "1.18.0")
    check("lookup при _ONLINE_REACHABLE=False → [] без сети",
          r == [] and opener.calls == 0,
          f"r={r}, calls={opener.calls}")


# --- 7. Источник «off»: онлайн отключён -----------------------------------
def test_source_off():
    old = os.environ.get("NETINV_CVE_SOURCE")
    os.environ["NETINV_CVE_SOURCE"] = "off"
    try:
        check("source()==off", c._cve_source() == "off")
        r = c.lookup_online("Apache httpd", "2.4.49")
        check("lookup_online при off → []", r == [], f"r={r}")
        c._ONLINE_REACHABLE = None
        ok = c.online_healthcheck(force=True)
        check("healthcheck при off → False", ok is False, f"ok={ok}")
    finally:
        if old is None:
            os.environ.pop("NETINV_CVE_SOURCE", None)
        else:
            os.environ["NETINV_CVE_SOURCE"] = old


# --- 8. teardown идемпотентен, алиасы совместимости -----------------------
def test_teardown_and_aliases():
    c._ONLINE_REACHABLE = True
    c.online_teardown()
    check("teardown сбрасывает _ONLINE_REACHABLE", c._ONLINE_REACHABLE is None)
    c.online_teardown()   # повтор — не должен падать
    check("teardown идемпотентен", c._ONLINE_REACHABLE is None)
    check("alias osv_teardown == online_teardown",
          c.osv_teardown is c.online_teardown)
    check("alias osv_healthcheck == online_healthcheck",
          c.osv_healthcheck is c.online_healthcheck)
    check("alias lookup_osv == lookup_circl",
          c.lookup_osv is c.lookup_circl)


def main():
    orig_opener = c._http_opener
    try:
        test_mapping()
        test_skip_without_request()
        test_parse_and_version_filter()
        test_version_affected()
        test_extract_helpers()
        test_graceful_degradation()
        test_source_off()
        test_teardown_and_aliases()
    finally:
        c._http_opener = orig_opener
        shutil.rmtree(_TMP_CACHE, ignore_errors=True)
    print("\n" + "=" * 60)
    if _failures:
        print(f"ПРОВАЛЕНО тестов: {len(_failures)}")
        for f in _failures:
            print("  - " + f)
        sys.exit(1)
    print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ")


if __name__ == "__main__":
    main()
