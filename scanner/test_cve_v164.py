#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты v1.6.4: динамическое разрешение vendor/product + версия из баннера.

Проверяется:
  1. _banner_tokens — извлечение значимых токенов (без версий/шумовых слов).
  2. _version_from_banner — извлечение версии из баннера (X14.3.6 → 14.3.6),
     отсутствие версии у номеров моделей (Tandberg-4145 → '').
  3. _best_product — скоринг product-слагов по токенам.
  4. _circl_browse — парсинг ответов browse (список / dict), graceful [].
  5. resolve_vendor_product — статика имеет приоритет; динамика через
     токены → vendor → product; graceful None при недоступности.
  6. lookup_circl (интеграция) — на реальном кейсе Tandberg:
     баннер без версии, версия извлекается из баннера, продукт динамически
     сопоставляется → tandberg/tandberg_mxp_endpoints, находка возвращается.
  7. Отсечка: при _ONLINE_REACHABLE=False динамика не дёргает сеть.

Запуск:  .venv/bin/python scanner/test_cve_v164.py
Тесты автономны: сеть НЕ дёргается (перехватываем opener).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cve_lookup as c

_failures = []

_TMP_CACHE = tempfile.mkdtemp(prefix="netinv_cve164_test_")
c._CACHE_DIR = _TMP_CACHE


def _clear_cache():
    for fn in os.listdir(_TMP_CACHE):
        try:
            os.remove(os.path.join(_TMP_CACHE, fn))
        except OSError:
            pass


def _reset_circl_caches():
    """Сбросить процессные кеши каталога CIRCL между тестами."""
    c._CIRCL_VENDORS = None
    c._CIRCL_PRODUCTS_CACHE = {}


def check(name, cond, detail=""):
    mark = "OK " if cond else "FAIL"
    if not cond:
        _failures.append(name + (f" — {detail}" if detail else ""))
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


# --- Заглушка opener с маршрутизацией по URL --------------------------------
def _rec(cve_id, base_score, severity, desc, versions=None):
    """Минимальная запись CVE 5.x (как в v1.6.3-тестах)."""
    cna = {
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": [{"cvssV3_1": {"baseScore": base_score,
                                  "baseSeverity": severity}}],
    }
    if versions is not None:
        cna["affected"] = [{"versions": versions}]
    return {"cveMetadata": {"cveId": cve_id},
            "containers": {"cna": cna}}


class _RouterOpener:
    """Опенер, отвечающий по URL: browse-vendors / browse-<vendor> / search.

    routes: dict {фрагмент_url: python-объект}. Совпадение по вхождению
    подстроки. Считает вызовы для проверки числа обращений к сети.
    """
    def __init__(self, routes):
        self.routes = routes
        self.calls = 0
        self.urls = []

    def open(self, req, timeout=None):
        self.calls += 1
        url = req.full_url if hasattr(req, "full_url") else str(req)
        self.urls.append(url)
        payload = None
        for frag, obj in self.routes.items():
            if frag in url:
                payload = obj
                break
        if payload is None:
            payload = []
        body = json.dumps(payload).encode("utf-8")
        outer_body = body

        class _R:
            status = 200

            def read(self_inner):
                return outer_body

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False
        return _R()


class _SentinelOpener:
    def __init__(self):
        self.calls = 0

    def open(self, *a, **k):
        self.calls += 1
        raise AssertionError("СЕТЕВОЙ ЗАПРОС НЕ ДОЛЖЕН БЫЛ УЙТИ")


# --- 1. _banner_tokens ------------------------------------------------------
def test_banner_tokens():
    cases = {
        "Tandberg-4145 VoIP server": ["tandberg"],
        "Apache httpd 2.4.49": ["apache"],
        "Tandberg-4145 VoIP server X14.3.6": ["tandberg"],  # X14 отброшен как артефакт версии
        "OpenSSH 8.2p1 Ubuntu": ["openssh", "ubuntu"],
        "": [],
        "http https ssl server": [],  # все шумовые
    }
    for banner, expected in cases.items():
        got = c._banner_tokens(banner)
        check(f"tokens «{banner}» → {expected}", got == expected,
              f"получено {got}")


# --- 2. _version_from_banner ------------------------------------------------
def test_version_from_banner():
    cases = {
        "Tandberg-4145 VoIP server X14.3.6": "14.3.6",
        "Apache httpd 2.4.49": "2.4.49",
        "nginx v1.2": "1.2",
        "Tandberg-4145 VoIP server": "",   # номер модели — не версия
        "product-500": "",                  # одна группа цифр
        "": "",
        "MyApp 3.0.1.2 build": "3.0.1.2",
    }
    for banner, expected in cases.items():
        got = c._version_from_banner(banner)
        check(f"version «{banner}» → {expected!r}", got == expected,
              f"получено {got!r}")


# --- 3. _best_product -------------------------------------------------------
def test_best_product():
    check("точное совпадение токену",
          c._best_product(["tandberg_mxp_endpoints", "other"],
                          ["tandberg"]) == "tandberg_mxp_endpoints")
    check("нет совпадений → None",
          c._best_product(["nginx", "apache"], ["zzzz"]) is None)
    check("пустой список продуктов → None",
          c._best_product([], ["tandberg"]) is None)
    # Точное равенство слага токену приоритетнее подстроки.
    check("точное равенство приоритетнее",
          c._best_product(["openssh", "openssh_portable"],
                          ["openssh"]) == "openssh")


# --- 4. _circl_browse -------------------------------------------------------
def test_circl_browse():
    # Список.
    op = _RouterOpener({"/api/browse/": ["tandberg", "apache", "nginx"]})
    c._http_opener = lambda: op
    got = c._circl_browse(None)
    check("browse список → нижний регистр",
          got == ["tandberg", "apache", "nginx"], f"получено {got}")

    # Dict со схемой {"product":[...]}.
    op2 = _RouterOpener({"/api/browse/tandberg":
                         {"product": ["Tandberg_MXP_Endpoints"]}})
    c._http_opener = lambda: op2
    got2 = c._circl_browse("tandberg")
    check("browse dict.product → список нижнего регистра",
          got2 == ["tandberg_mxp_endpoints"], f"получено {got2}")

    # Ошибка сети → [].
    op3 = _SentinelOpener()
    c._http_opener = lambda: op3
    got3 = c._circl_browse("boom")
    check("browse при ошибке → []", got3 == [], f"получено {got3}")


# --- 5. resolve_vendor_product ---------------------------------------------
def test_resolve_static_priority():
    """Статическая таблица имеет приоритет — сеть не дёргается."""
    _reset_circl_caches()
    op = _SentinelOpener()      # взорвётся при любом сетевом вызове
    c._http_opener = lambda: op
    c._ONLINE_REACHABLE = True
    got = c.resolve_vendor_product("Apache httpd 2.4.49")
    check("resolve статика apache → (apache,http_server,True) без сети",
          got == ("apache", "http_server", True) and op.calls == 0,
          f"получено {got}, calls={op.calls}")


def test_resolve_dynamic_tandberg():
    """Динамика: Tandberg не в статике → каталог CIRCL → tandberg/...endpoints."""
    _reset_circl_caches()
    routes = {
        "/api/browse/tandberg": ["tandberg_mxp_endpoints"],  # продукты vendor
        "/api/browse/": ["tandberg", "apache", "cisco"],     # все vendor-слаги
    }
    op = _RouterOpener(routes)
    c._http_opener = lambda: op
    c._ONLINE_REACHABLE = True
    got = c.resolve_vendor_product("Tandberg-4145 VoIP server")
    check("resolve динамика Tandberg → (tandberg,tandberg_mxp_endpoints,True)",
          got == ("tandberg", "tandberg_mxp_endpoints", True),
          f"получено {got}")


def test_resolve_offline_no_network():
    """При _ONLINE_REACHABLE=False динамика не дёргает сеть → None."""
    _reset_circl_caches()
    op = _SentinelOpener()
    c._http_opener = lambda: op
    c._ONLINE_REACHABLE = False
    got = c.resolve_vendor_product("Tandberg-4145 VoIP server")
    check("resolve offline → None без сети",
          got is None and op.calls == 0, f"получено {got}, calls={op.calls}")
    c._ONLINE_REACHABLE = True   # восстановить для последующих тестов


def test_resolve_unknown_none():
    """Неизвестный баннер без совпадений vendor → None."""
    _reset_circl_caches()
    routes = {"/api/browse/": ["apache", "nginx", "cisco"]}
    op = _RouterOpener(routes)
    c._http_opener = lambda: op
    c._ONLINE_REACHABLE = True
    got = c.resolve_vendor_product("Zzzunknown Daemon")
    check("resolve неизвестный баннер → None", got is None, f"получено {got}")


# --- 6. lookup_circl: интеграция на кейсе Tandberg -------------------------
_CIRCL_TANDBERG = {
    "results": {
        "nvd": [
            ["CVE-2009-3947", _rec(
                "CVE-2009-3947", 10.0, "CRITICAL",
                "Tandberg VCS before X5.2 default credentials.",
                [{"version": "0", "lessThan": "14.99",
                  "status": "affected"}])],
        ],
        "cvelistv5": [],
    },
    "total_count": 1,
}


def test_lookup_circl_tandberg_end_to_end():
    """Баннер «Tandberg-4145 VoIP server X14.3.6» без отдельной версии:
    версия извлекается из баннера, продукт динамически сопоставляется,
    CVE находится."""
    _reset_circl_caches()
    _clear_cache()
    routes = {
        "/api/search/tandberg/tandberg_mxp_endpoints": _CIRCL_TANDBERG,
        "/api/browse/tandberg": ["tandberg_mxp_endpoints"],
        "/api/browse/": ["tandberg", "apache", "cisco"],
    }
    op = _RouterOpener(routes)
    c._http_opener = lambda: op
    c._ONLINE_REACHABLE = True
    # Версия НЕ передаётся отдельно — она внутри баннера.
    r = c.lookup_circl("Tandberg-4145 VoIP server X14.3.6", "")
    ids = [f.get("cve_id") for f in r]
    check("lookup Tandberg находит CVE-2009-3947",
          "CVE-2009-3947" in ids, f"получено {ids}")
    check("lookup Tandberg сделал сетевые вызовы (browse+search)",
          op.calls >= 2, f"calls={op.calls}")


def test_lookup_circl_offline_skip():
    """При недоступном источнике lookup_circl не шлёт запрос → []."""
    _reset_circl_caches()
    _clear_cache()
    op = _SentinelOpener()
    c._http_opener = lambda: op
    c._ONLINE_REACHABLE = False
    r = c.lookup_circl("Tandberg-4145 VoIP server X14.3.6", "")
    check("lookup offline → [] без сети",
          r == [] and op.calls == 0, f"получено {r}, calls={op.calls}")
    c._ONLINE_REACHABLE = True


def main():
    print("=" * 60)
    print("Тесты CVE v1.6.4 (динамика vendor/product + версия из баннера)")
    print("=" * 60)
    test_banner_tokens()
    test_version_from_banner()
    test_best_product()
    test_circl_browse()
    test_resolve_static_priority()
    test_resolve_dynamic_tandberg()
    test_resolve_offline_no_network()
    test_resolve_unknown_none()
    test_lookup_circl_tandberg_end_to_end()
    test_lookup_circl_offline_skip()
    print("\n" + "=" * 60)
    if _failures:
        print(f"ПРОВАЛЕНО тестов: {len(_failures)}")
        for f in _failures:
            print("  - " + f)
        sys.exit(1)
    print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ")


if __name__ == "__main__":
    main()
