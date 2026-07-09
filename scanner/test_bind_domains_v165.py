"""Тест доработки 6 (v1.6.5): при привязке поддомена его родительский
домен автоматически добавляется в target_domains и виден в описании
объекта.

Использует временную БД (NETINV_DB) во временном каталоге.
"""
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


def _fresh_db():
    tmp = tempfile.mkdtemp(prefix="netinv_bind_")
    dbpath = os.path.join(tmp, "data.db")
    os.environ["NETINV_DB"] = dbpath
    # Переимпортируем db с новым путём.
    for m in list(sys.modules):
        if m == "scanner.db" or m == "db":
            del sys.modules[m]
    from scanner import db as _db
    _db.init_db()
    return _db


def main():
    db = _fresh_db()
    checks = []

    def chk(name, cond):
        checks.append((name, bool(cond)))
        print(("OK  " if cond else "FAIL") + "  " + name)

    tid = db.add_target("Тест", "192.168.56.0/24", "desc")

    # Три поддомена под двумя родительскими доменами.
    db.add_subdomain(tid, "example.ru", "www.example.ru", ip="10.0.0.1", tool="dnsrecon")
    db.add_subdomain(tid, "example.ru", "mail.example.ru", ip="10.0.0.2", tool="dnsrecon")
    db.add_subdomain(tid, "corp.local", "vpn.corp.local", ip="10.0.0.3", tool="dnsmap")

    # До привязки — доменов в объекте нет.
    chk("до привязки target_domains пуст", db.domains_for_target(tid) == [])

    # Привязать один поддомен → появляется его родитель.
    db.set_subdomain_bound(tid, "www.example.ru", True)
    added = db.sync_bound_domains_to_target(tid)
    chk("bind_one добавил 1 домен", added == 1)
    chk("example.ru в описании объекта", "example.ru" in db.domains_for_target(tid))
    chk("corp.local ещё НЕ добавлен", "corp.local" not in db.domains_for_target(tid))

    # Повторная синхронизация не создаёт дубликатов.
    added2 = db.sync_bound_domains_to_target(tid)
    chk("повторная синхронизация не добавляет дубликатов", added2 == 0)
    chk("example.ru встречается один раз",
        db.domains_for_target(tid).count("example.ru") == 1)

    # Привязать все новые → появляется второй родитель.
    n = db.set_all_subdomains_bound(tid, True, only_present=True)
    added3 = db.sync_bound_domains_to_target(tid)
    doms = set(db.domains_for_target(tid))
    chk("после bind_all оба родителя присутствуют",
        {"example.ru", "corp.local"} <= doms)
    chk("bind_all добавил ровно 1 новый домен (corp.local)", added3 == 1)

    # list_target_domains должен вернуть эти домены (для index.html).
    ltd = [d["domain"] for d in db.list_target_domains(tid)]
    chk("list_target_domains содержит оба домена",
        {"example.ru", "corp.local"} <= set(ltd))

    failed = [n for n, ok in checks if not ok]
    print()
    if failed:
        print(f"ПРОВАЛЕНО: {len(failed)} из {len(checks)}")
        sys.exit(1)
    print(f"ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ: {len(checks)}")


if __name__ == "__main__":
    main()
