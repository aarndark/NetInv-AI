#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты DNS-верификации поддоменов (v1.6.4 → обновлено под П.4 v1.6.5).

П.4 (v1.6.5): валидность DNS-записи — ТОЛЬКО прямой резолв (forward).
PTR (обратная зона) не влияет на артефакт — только пометка.

Проверяется:
  1. reverse_lookup — валидация IP, graceful [] при отсутствии PTR.
  2. verify_subdomain — матрица (П.4):
       - нет IP → артефакт;
       - forward OK (независимо от PTR) → подтверждён;
       - forward не содержит IP → артефакт;
       - forward OK + PTR отсутствует → подтверждён + ptr_mismatch;
       - forward OK + PTR чужого домена → подтверждён + ptr_mismatch;
       - forward OK + PTR того же apex → подтверждён, ptr_mismatch=False.
  3. recon_domain (apex) — поддомены получают is_artifact/verify_reason,
     только подтверждённые (forward) дают IP к сканированию.

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
        check("forward OK + PTR сам → подтверждён",
              r["is_artifact"] == 0 and not r["ptr_mismatch"], str(r))

        r = d.verify_subdomain("wrongip.example.ru", "1.2.3.4")
        check("forward не содержит IP → артефакт",
              r["is_artifact"] == 1 and not r["forward_ok"], str(r))

        # П.4: PTR отсутствует, но forward OK → НЕ артефакт, пометка.
        r = d.verify_subdomain("noptr.example.ru", "5.5.5.5")
        check("forward OK + PTR отсутствует → подтверждён + пометка",
              r["is_artifact"] == 0 and r["ptr_mismatch"]
              and r["ptr_note"] == "PTR отсутствует", str(r))

        # П.4: PTR чужого домена, но forward OK → НЕ артефакт, пометка.
        r = d.verify_subdomain("foreign.example.ru", "6.6.6.6")
        check("forward OK + PTR чужой домен → подтверждён + пометка",
              r["is_artifact"] == 0 and r["ptr_mismatch"]
              and "не соответствует" in r["ptr_note"], str(r))

        # forward содержит IP + PTR указывает на ИНОЕ имя ТОГО ЖЕ apex → OK.
        stub.forward["multi.example.ru"] = ["7.7.7.7"]
        r = d.verify_subdomain("multi.example.ru", "7.7.7.7")
        check("forward OK + PTR того же apex → подтверждён, без пометки",
              r["is_artifact"] == 0 and r["reverse_ok"]
              and not r["ptr_mismatch"], str(r))
    finally:
        stub.restore()


# --- 3. recon_domain: поддомены с признаком артефакта -----------------------
def test_recon_domain_artifacts():
    subs = [
        {"parent": "example.ru", "subdomain": "good.example.ru",
         "ip": "1.2.3.4", "tool": "dnsmap"},
        {"parent": "example.ru", "subdomain": "bad.example.ru",
         "ip": "8.8.8.8", "tool": "dnsrecon"},     # PTR чужой, но forward OK
        {"parent": "example.ru", "subdomain": "nofwd.example.ru",
         "ip": "3.3.3.3", "tool": "dnsrecon"},     # forward НЕ содержит IP → артефакт
        {"parent": "example.ru", "subdomain": "noip.example.ru",
         "ip": None, "tool": "dnsmap"},            # нет IP → артефакт
    ]
    stub = _DNSStub(
        forward={
            "example.ru": ["1.2.3.4"],
            "good.example.ru": ["1.2.3.4"],
            "bad.example.ru": ["8.8.8.8"],
            "nofwd.example.ru": ["9.9.9.9"],   # forward не содержит заявл. 3.3.3.3
        },
        reverse={
            "1.2.3.4": ["good.example.ru"],
            "8.8.8.8": ["dns.google"],   # чужой домен (П.4: лишь пометка)
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
        # П.4: forward OK, но PTR чужой → НЕ артефакт, есть PTR-пометка.
        check("bad (чужой PTR, forward OK) → НЕ артефакт + пометка",
              by_name["bad.example.ru"]["is_artifact"] == 0
              and by_name["bad.example.ru"].get("ptr_mismatch")
              and "⚠" in by_name["bad.example.ru"]["verify_reason"],
              str(by_name.get("bad.example.ru")))
        check("nofwd (forward не содержит IP) → артефакт",
              by_name["nofwd.example.ru"]["is_artifact"] == 1,
              str(by_name.get("nofwd.example.ru")))
        check("noip → артефакт",
              by_name["noip.example.ru"]["is_artifact"] == 1,
              str(by_name.get("noip.example.ru")))
        # П.4: IP дают все forward-подтверждённые (good + bad), но НЕ артефакты.
        check("к сканированию идут forward-подтверждённые IP (good+bad)",
              "1.2.3.4" in res["ips"] and "8.8.8.8" in res["ips"]
              and "9.9.9.9" not in res["ips"],
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
