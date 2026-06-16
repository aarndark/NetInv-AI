#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
seed_test.py — интеграционный тест без реального nmap.

Засевает в БД два запуска ОСНОВНОГО класса (main) для одного объекта,
имитируя изменения между сканированиями (новый IP, пропавший IP, новые/
пропавшие порты и сервисы), затем прогоняет diff_engine.update_host_states.
Также создаёт пользователя cpt для входа в web. Используется для проверки
подсветки и текста «Отличий», а также для скриншотов web-интерфейса.
"""
import os
import sys
import datetime as dt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db          # noqa: E402
import diff_engine  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402


def _run(target_id, when, scan_class, profile, nmap_args, options_json=None):
    return db.create_run(target_id, when, profile, nmap_args,
                         scan_class=scan_class, options_json=options_json)


def _host(run_id, ip, hostname, state, when, anp=0, ports=()):
    hid = db.add_host(run_id, ip, hostname, state, when, alive_no_ports=anp)
    for (port, proto, pstate, svc, prod, ver, conf) in ports:
        db.add_port(hid, port, proto, pstate, svc, prod, ver, "", conf)
    return hid


def main():
    db.init_db()

    # --- пользователь cpt (для входа в web) ---
    db.upsert_user("admin", generate_password_hash("admin123", method="pbkdf2:sha256"),
                   in_cpt=1)
    # Пользователь БЕЗ доступа (для проверки отказа).
    db.upsert_user("guest", generate_password_hash("guest123", method="pbkdf2:sha256"),
                   in_cpt=0)
    print("[+] Пользователи: admin (cpt), guest (без доступа)")

    # --- объект ---
    tid = db.add_target("Тестовый сегмент", "192.168.56.0/24",
                        "Демо-объект для интеграционного теста")
    print(f"[+] Объект id={tid}")

    MAIN_ARGS = "nmap -sT -T3 (balanced, обход SYN-защиты, NSE, web, alive_no_ports)"

    # === Запуск 1 (основной) — базовый ===
    t1 = (dt.datetime.now() - dt.timedelta(days=2)).isoformat(timespec="seconds")
    r1 = _run(tid, t1, "main", "balanced/evasion", MAIN_ARGS)
    _host(r1, "192.168.56.10", "web01.local", "up", t1, ports=[
        (80, "tcp", "open", "http", "nginx", "1.24", "confirmed"),
        (443, "tcp", "open", "https", "nginx", "1.24", "confirmed"),
    ])
    _host(r1, "192.168.56.20", "db01.local", "up", t1, ports=[
        (5432, "tcp", "open", "postgresql", "PostgreSQL", "15", "confirmed"),
    ])
    # Хост без подтверждённых портов — возможный артефакт Palo Alto.
    _host(r1, "192.168.56.30", "ghost.local", "up", t1, ports=[
        (22, "tcp", "open", "ssh", "", "", "syncookie_suspect"),
    ])
    db.finish_run(r1, "done", t1, 3)
    diff_engine.update_host_states(tid, r1, scan_class="main")
    print(f"[+] Запуск 1 (main) id={r1}: первое обнаружение 3 IP")

    # === Запуск 2 (основной) — с изменениями ===
    # .10: +новый порт 8080(http-proxy), -пропал 443; .20: без изменений;
    # .30: ПРОПАЛ; +новый IP .40.
    t2 = dt.datetime.now().isoformat(timespec="seconds")
    r2 = _run(tid, t2, "main", "balanced/evasion", MAIN_ARGS)
    _host(r2, "192.168.56.10", "web01.local", "up", t2, ports=[
        (80, "tcp", "open", "http", "nginx", "1.24", "confirmed"),
        (8080, "tcp", "open", "http-proxy", "Apache", "2.4", "confirmed"),
    ])
    _host(r2, "192.168.56.20", "db01.local", "up", t2, ports=[
        (5432, "tcp", "open", "postgresql", "PostgreSQL", "15", "confirmed"),
    ])
    # .30 отсутствует -> должен стать presence='gone' с примечанием «IP не найден».
    # Новый IP .40.
    _host(r2, "192.168.56.40", "new-host.local", "up", t2, ports=[
        (3389, "tcp", "open", "ms-wbt-server", "Microsoft Terminal Services", "", "confirmed"),
    ])
    db.finish_run(r2, "done", t2, 3)
    diff_engine.update_host_states(tid, r2, scan_class="main")
    print(f"[+] Запуск 2 (main) id={r2}: изменения посеяны")

    # === Один расширенный запуск (для отображения класса/опций в истории) ===
    t3 = dt.datetime.now().isoformat(timespec="seconds")
    opts = ('{"syn_mode":"direct","profile":"fast","ports":"top-100",'
            '"extra_nse":true,"do_web":false,"advanced_anp":false}')
    r3 = _run(tid, t3, "advanced", "fast/direct", "nmap -sS -T4 --top-ports 100",
              options_json=opts)
    _host(r3, "192.168.56.10", "web01.local", "up", t3, ports=[
        (80, "tcp", "open", "http", "nginx", "1.24", "confirmed"),
    ])
    db.finish_run(r3, "done", t3, 1)
    diff_engine.update_host_states(tid, r3, scan_class="advanced")
    print(f"[+] Запуск 3 (advanced) id={r3}")

    # --- проверка report_rows + diff текст ---
    print("\n=== report_rows(main) ===")
    rows = db.report_rows(tid, scan_class="main")
    for r in rows:
        print(" ", r.get("ip"), "| presence=", r.get("presence"),
              "| first_seen=", r.get("first_seen"))

    print("\nИтоговый объект id:", tid)


if __name__ == "__main__":
    main()
