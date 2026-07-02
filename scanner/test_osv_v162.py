#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты v1.6.2: маппинг nmap→OSV, отсечка заведомо битых запросов,
graceful degradation без VPN, корректная форма payload к OSV.

Запуск:  .venv/bin/python scanner/test_osv_v162.py
Тесты автономны: сеть НЕ дёргается (перехватываем opener), VPN не поднимается
(перехватываем vpnctl). Проверяется именно логика, а не внешняя доступность.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cve_lookup as c
import vpnctl

_failures = []

# Изолируем файловый кеш от боевого: каждый тест чистит временную папку.
_TMP_CACHE = tempfile.mkdtemp(prefix="netinv_osv_test_")
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


# --- 1. Таблица маппинга map_to_osv ---------------------------------------
def test_mapping():
    cases = {
        "Apache httpd": ("apache", "OSS-Fuzz", True),
        "Apache httpd 2.4.49": ("apache", "OSS-Fuzz", True),
        "apache2": ("apache", "OSS-Fuzz", True),
        "nginx": ("nginx", "OSS-Fuzz", True),
        "OpenSSH": ("openssh", "OSS-Fuzz", True),
        "OpenSSH 8.2p1": ("openssh", "OSS-Fuzz", True),
        "ssh": ("openssh", "OSS-Fuzz", True),
        "openssl": ("openssl", "OSS-Fuzz", True),
        "curl": ("curl", "OSS-Fuzz", True),
        "sqlite": ("sqlite3", "OSS-Fuzz", True),
        "PostgreSQL": ("postgresql", "OSS-Fuzz", True),
        "Golang net/http server": ("stdlib", "Go", True),
        "Python": ("cpython", "OSS-Fuzz", True),
    }
    for product, expected in cases.items():
        got = c.map_to_osv(product)
        check(f"map «{product}» → {expected}", got == expected, f"получено {got}")

    # Продукты БЕЗ сопоставления → None (онлайн-запрос не шлём).
    for product in ["Cisco Expressway E", "Microsoft IIS", "lighttpd",
                    "unknown-daemon", "", None]:
        got = c.map_to_osv(product)
        check(f"map «{product}» → None (нет экосистемы)", got is None,
              f"получено {got}")


# --- 2. Отсечка: без версии / без маппинга запрос НЕ отправляется ----------
class _SentinelOpener:
    """Опенер, который «взрывается» при любом сетевом вызове.

    Используется, чтобы доказать: заведомо битые запросы к сети НЕ уходят.
    """
    def __init__(self):
        self.calls = 0

    def open(self, *a, **k):
        self.calls += 1
        raise AssertionError("СЕТЕВОЙ ЗАПРОС НЕ ДОЛЖЕН БЫЛ УЙТИ")


def test_skip_without_request(monkey):
    monkey["opener"] = _SentinelOpener()
    c._osv_opener = lambda: monkey["opener"]
    c._OSV_REACHABLE = True   # притворяемся, что OSV достижим (VPN поднят)
    _clear_cache()

    # a) Нет сопоставления → запрос не уходит, возвращается [].
    r = c.lookup_osv("Cisco Expressway E", "X8.11.4")
    check("нет маппинга → [] и без сети", r == [] and monkey["opener"].calls == 0,
          f"r={r}, calls={monkey['opener'].calls}")

    # b) Есть маппинг, но нет версии (need_ver=True) → запрос не уходит.
    _clear_cache()
    r = c.lookup_osv("Apache httpd", "")
    check("маппинг без версии → [] и без сети",
          r == [] and monkey["opener"].calls == 0,
          f"r={r}, calls={monkey['opener'].calls}")


# --- 3. Корректная форма payload при валидном запросе ---------------------
class _CaptureOpener:
    """Перехватывает Request, отдаёт заранее заданный JSON-ответ."""
    def __init__(self, response_obj):
        self.captured = None
        self._resp = json.dumps(response_obj).encode("utf-8")

    def open(self, req, timeout=None):
        self.captured = json.loads(req.data.decode("utf-8"))
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


def test_payload_shape(monkey):
    cap = _CaptureOpener({"vulns": [
        {"id": "GO-2023-2041", "aliases": ["CVE-2023-39318"],
         "summary": "тестовая уязвимость",
         "severity": [{"score": "7.5"}]}
    ]})
    c._osv_opener = lambda: cap
    c._OSV_REACHABLE = True
    _clear_cache()

    r = c.lookup_osv("Golang net/http server", "1.21.0")
    q = cap.captured
    check("payload содержит package.name+ecosystem",
          q and q.get("package", {}).get("name") == "stdlib"
          and q["package"].get("ecosystem") == "Go",
          f"q={q}")
    check("payload содержит version верхнего уровня",
          q and q.get("version") == "1.21.0", f"q={q}")
    check("CVE-алиас извлечён",
          len(r) == 1 and r[0]["cve_id"] == "CVE-2023-39318", f"r={r}")


# --- 4. Graceful degradation: VPN недоступен → онлайн-CVE выключены --------
def test_graceful_no_vpn(monkey):
    # Эмулируем «adguardvpn-cli не установлен».
    orig_available = vpnctl.available
    orig_enabled = vpnctl._enabled
    vpnctl.available = lambda: False
    vpnctl._enabled = lambda: True     # авто-VPN включён, но CLI нет
    vpnctl._failed = False
    vpnctl._active = False
    vpnctl._refcount = 0
    try:
        c._OSV_REACHABLE = None
        ok = c.osv_healthcheck(force=True)
        check("healthcheck без VPN → False (degradation)", ok is False,
              f"ok={ok}")
        check("_OSV_REACHABLE выставлен в False",
              c._OSV_REACHABLE is False)

        # При недоступном OSV lookup сразу отдаёт [] без сети.
        opener = _SentinelOpener()
        c._osv_opener = lambda: opener
        _clear_cache()
        r = c.lookup_osv("nginx", "1.18.0")
        check("lookup при _OSV_REACHABLE=False → [] без сети",
              r == [] and opener.calls == 0,
              f"r={r}, calls={opener.calls}")
    finally:
        vpnctl.available = orig_available
        vpnctl._enabled = orig_enabled


# --- 5. teardown идемпотентен и не бросает --------------------------------
def test_teardown_idempotent():
    orig_enabled = vpnctl._enabled
    vpnctl._enabled = lambda: True
    vpnctl._active = False
    vpnctl._refcount = 0
    try:
        c.osv_teardown()          # первый вызов
        c.osv_teardown()          # повторный — не должен падать
        check("teardown идемпотентен, сбрасывает кеш",
              c._OSV_REACHABLE is None)
    finally:
        vpnctl._enabled = orig_enabled


def main():
    monkey = {}
    # Сохраняем оригиналы для восстановления между тестами.
    orig_opener = c._osv_opener
    try:
        test_mapping()
        test_skip_without_request(monkey)
        test_payload_shape(monkey)
        test_graceful_no_vpn(monkey)
        test_teardown_idempotent()
    finally:
        c._osv_opener = orig_opener
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
