"""Тест доработок v1.6.6: обход сбоя планировщика NSE/nsock (повтор nmap
без --script при аварийном завершении сигналом) + пофазовый статус запуска
(dns/nmap/webscan -> ok|failed|skipped|off) для колонки «Ошибки
сканирования» страницы «История сканирований».

Использует временную БД (NETINV_DB) во временном каталоге.
"""
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)


def _fresh_db():
    tmp = tempfile.mkdtemp(prefix="netinv_nmapcrash_")
    dbpath = os.path.join(tmp, "data.db")
    os.environ["NETINV_DB"] = dbpath
    for m in list(sys.modules):
        if m in ("db", "scanner"):
            del sys.modules[m]
    import db as _db
    _db.init_db()
    return _db


def main():
    db = _fresh_db()
    import scanner

    checks = []

    def chk(name, cond):
        checks.append((name, bool(cond)))
        print(("OK  " if cond else "FAIL") + "  " + name)

    # --- 1. _strip_nse_scripts() -----------------------------------------
    cmd = ["nmap", "-sT", "-sV", "--script",
           "banner,http-title,http-headers,ssl-cert", "-oX", "/tmp/x.xml",
           "10.0.0.0/24"]
    stripped = scanner._strip_nse_scripts(cmd)
    chk("_strip_nse_scripts убирает --script и его значение",
        "--script" not in stripped
        and "banner,http-title,http-headers,ssl-cert" not in stripped)
    chk("_strip_nse_scripts сохраняет остальные опции",
        stripped == ["nmap", "-sT", "-sV", "-oX", "/tmp/x.xml", "10.0.0.0/24"])

    # --script в самом конце команды (без хвоста) — не должен ничего ломать.
    cmd2 = ["nmap", "-sT", "--script", "banner"]
    chk("_strip_nse_scripts корректно работает, если --script последний",
        scanner._strip_nse_scripts(cmd2) == ["nmap", "-sT"])

    # Без --script вообще — команда не меняется.
    cmd3 = ["nmap", "-sT", "10.0.0.0/24"]
    chk("_strip_nse_scripts не трогает команду без --script",
        scanner._strip_nse_scripts(cmd3) == cmd3)

    # --- 2. phases_json: миграция колонки + запись/чтение ----------------
    tid = db.add_target("Тест", "10.0.0.0/24", "desc")
    started = "2026-07-10T09:00:00"
    run_id = db.create_run(tid, started, "stealth/evasion", "nmap ...",
                           scan_class="main")
    chk("create_run вернул run_id", isinstance(run_id, int))

    import sqlite3
    with sqlite3.connect(db.DB_PATH) as c:
        cols = [r[1] for r in c.execute("PRAGMA table_info(scan_runs)")]
    chk("колонка phases_json существует в scan_runs", "phases_json" in cols)

    import json
    phases = {"dns": "ok", "nmap": "failed", "webscan": "skipped"}
    db.set_run_phases_json(run_id, json.dumps(phases, ensure_ascii=False))
    full = db.get_run_full(run_id)
    chk("get_run_full возвращает phases как dict",
        isinstance(full.get("phases"), dict))
    chk("get_run_full.phases содержит верные значения",
        full["phases"].get("dns") == "ok"
        and full["phases"].get("nmap") == "failed"
        and full["phases"].get("webscan") == "skipped")

    # set_run_phases_json(None, ...) не должен падать (ранняя стадия скана).
    try:
        db.set_run_phases_json(None, json.dumps({}))
        chk("set_run_phases_json(None, ...) не выбрасывает исключение", True)
    except Exception:  # noqa: BLE001
        chk("set_run_phases_json(None, ...) не выбрасывает исключение", False)

    # Запуск без phases_json — get_run_full возвращает {} (не падает).
    run_id2 = db.create_run(tid, started, "stealth/evasion", "nmap ...",
                            scan_class="main")
    full2 = db.get_run_full(run_id2)
    chk("get_run_full без phases_json возвращает {}", full2.get("phases") == {})

    # --- 3. _finalize_cancelled(): дозаполнение skipped -------------------
    class _FakeSlog:
        def section(self, *a, **k):
            pass

        def close(self):
            pass

    run_id3 = db.create_run(tid, started, "stealth/evasion", "nmap ...",
                            scan_class="main")
    scanner._finalize_cancelled(run_id3, _FakeSlog(), lambda m: None, tid,
                                "main", phases={"dns": "ok"})
    full3 = db.get_run_full(run_id3)
    chk("_finalize_cancelled сохраняет уже известную фазу dns",
        full3["phases"].get("dns") == "ok")
    chk("_finalize_cancelled дозаполняет nmap/webscan как skipped",
        full3["phases"].get("nmap") == "skipped"
        and full3["phases"].get("webscan") == "skipped")

    failed = [n for n, ok in checks if not ok]
    print()
    if failed:
        print(f"ПРОВАЛЕНО: {len(failed)} из {len(checks)}")
        sys.exit(1)
    print(f"ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ: {len(checks)}")


if __name__ == "__main__":
    main()
