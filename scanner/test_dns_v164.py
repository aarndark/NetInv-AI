#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты v1.6.4 (Правка 1): верификация поддоменов по IP + артефакты.

Проверяется:
  1. reverse_lookup — валидация IP, graceful [] при отсутствии PTR.
  2. verify_subdomain — матрица прямая×обратная проверок:
       - нет IP → артефакт;
       - forward+reverse OK → подтверждён;
       - forward не содержит IP → артефакт;
       - PTR отсутствует → артефакт;
       - PTR другого домена → артефакт;
       - PTR того же apex-домена → подтверждён.
  3. recon_domain (apex) — поддомены получают is_artifact/verify_reason,
     только подтверждённые дают IP к сканированию (result['ips']).

Тесты автономны: сеть НЕ дёргается — подменяем resolve_host/reverse_lookup.

Запуск:  .venv/bin/python scanner/test_dns_v164.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns_recon as d

_failures = []


def check(name, cond, detail=""):
    mark = "OK " if cond else "FAIL"
    if not cond:
        _failures.append(name + (f" — {detail}" if detail else ""))
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


# --- Подмена сетевых функций управляемыми таблицами -------------------------
class _DNSStub:
    """Заменяет resolve_host и reverse_lookup детерминированными таблицами."""
    def __init__(self, forward=None, reverse=None, subs=None):
        self.forward = forward or {}   # имя -> [ip]
        self.reverse = reverse or {}   # ip   -> [PTR-имена]
        self.subs = subs or []         # результат discover_subdomains

    def install(self):
        self._orig_resolve = d.resolve_host
        self._orig_reverse = d.reverse_lookup
        self._orig_discover = d.discover_subdomains
        d.resolve_host = lambda name, timeout=d.RESOLVE_TIMEOUT: \
            list(self.forward.get((name or "").strip().lower().rstrip("."), []))
        d.reverse_lookup = lambda ip, timeout=d.RESOLVE_TIMEOUT: \
            list(self.reverse.get((ip or "").strip(), []))
        # Проглатываем любые доп. kwargs (напр. detail, добавленный в v1.6.4),
        # чтобы стаб не ломался при расширении сигнатуры discover_subdomains.
        d.discover_subdomains = lambda domain, brute=False, log=None, **kw: \
            (list(self.subs), ["dnsmap"], [])

    def restore(self):
        d.resolve_host = self._orig_resolve
        d.reverse_lookup = self._orig_reverse
        d.discover_subdomains = self._orig_discover


# --- 1. reverse_lookup: валидация входа -------------------------------------
def test_reverse_lookup_input():
    check("reverse_lookup('') → []", d.reverse_lookup("") == [])
    check("reverse_lookup('not-an-ip') → []", d.reverse_lookup("nope") == [])


# --- 2. verify_subdomain: матрица случаев -----------------------------------
def test_verify_matrix():
    # Нет IP → артефакт.
    r = d.verify_subdomain("a.example.ru", None)
    check("нет IP → артефакт", r["is_artifact"] == 1, str(r))

    stub = _DNSStub(
        forward={
            "ok.example.ru": ["1.2.3.4"],
            "wrongip.example.ru": ["9.9.9.9"],   # не содержит заявленный IP
            "noptr.example.ru": ["5.5.5.5"],
            "foreign.example.ru": ["6.6.6.6"],
        },
        reverse={
            "1.2.3.4": ["ok.example.ru"],          # PTR = сам поддомен
            "9.9.9.9": ["ok.example.ru"],
            "5.5.5.5": [],                          # PTR отсутствует
            "6.6.6.6": ["host.otherdomain.net"],    # PTR другого домена
            "7.7.7.7": ["mail.example.ru"],         # PTR того же apex
        },
    )
    stub.install()
    try:
        r = d.verify_subdomain("ok.example.ru", "1.2.3.4")
        check("forward+reverse OK → подтверждён", r["is_artifact"] == 0, str(r))

        r = d.verify_subdomain("wrongip.example.ru", "1.2.3.4")
        check("forward не содержит IP → артефакт",
              r["is_artifact"] == 1 and not r["forward_ok"], str(r))

        r = d.verify_subdomain("noptr.example.ru", "5.5.5.5")
        check("PTR отсутствует → артефакт",
              r["is_artifact"] == 1 and not r["reverse_ok"], str(r))

        r = d.verify_subdomain("foreign.example.ru", "6.6.6.6")
        check("PTR другого домена → артефакт",
              r["is_artifact"] == 1 and not r["reverse_ok"], str(r))

        # forward содержит IP + PTR указывает на ИНОЕ имя ТОГО ЖЕ apex → OK.
        stub.forward["multi.example.ru"] = ["7.7.7.7"]
        r = d.verify_subdomain("multi.example.ru", "7.7.7.7")
        check("PTR того же apex → подтверждён",
              r["is_artifact"] == 0 and r["reverse_ok"], str(r))
    finally:
        stub.restore()


# --- 3. recon_domain: поддомены с признаком артефакта -----------------------
def test_recon_domain_artifacts():
    subs = [
        {"parent": "example.ru", "subdomain": "good.example.ru",
         "ip": "1.2.3.4", "tool": "dnsmap"},
        {"parent": "example.ru", "subdomain": "bad.example.ru",
         "ip": "8.8.8.8", "tool": "dnsrecon"},     # PTR чужой → артефакт
        {"parent": "example.ru", "subdomain": "noip.example.ru",
         "ip": None, "tool": "dnsmap"},            # нет IP → артефакт
    ]
    stub = _DNSStub(
        forward={
            "example.ru": ["1.2.3.4"],
            "good.example.ru": ["1.2.3.4"],
            "bad.example.ru": ["8.8.8.8"],
        },
        reverse={
            "1.2.3.4": ["good.example.ru"],
            "8.8.8.8": ["dns.google"],   # чужой домен
        },
        subs=subs,
    )
    stub.install()
    try:
        res = d.recon_domain("example.ru", brute=False, log=None)
        by_name = {s["subdomain"]: s for s in res["subdomains"]}
        check("good → не артефакт",
              by_name["good.example.ru"]["is_artifact"] == 0,
              str(by_name.get("good.example.ru")))
        check("bad (чужой PTR) → артефакт",
              by_name["bad.example.ru"]["is_artifact"] == 1,
              str(by_name.get("bad.example.ru")))
        check("noip → артефакт",
              by_name["noip.example.ru"]["is_artifact"] == 1,
              str(by_name.get("noip.example.ru")))
        # Только подтверждённый good даёт IP к сканированию.
        check("к сканированию идёт только IP подтверждённого поддомена",
              "1.2.3.4" in res["ips"] and "8.8.8.8" not in res["ips"],
              f"ips={res['ips']}")
    finally:
        stub.restore()


def main():
    print("=" * 60)
    print("Тесты DNS v1.6.4 (верификация поддоменов + артефакты)")
    print("=" * 60)
    test_reverse_lookup_input()
    test_verify_matrix()
    test_recon_domain_artifacts()
    print("\n" + "=" * 60)
    if _failures:
        print(f"ПРОВАЛЕНО тестов: {len(_failures)}")
        for f in _failures:
            print("  - " + f)
        sys.exit(1)
    print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ")


if __name__ == "__main__":
    main()
