"""Тест доработки 6 (v1.6.5) + исправление бага 1 (v1.6.7): при привязке
поддомена он сам (FQDN) и его родительский домен добавляются в
target_domains и видны в столбце «Домены» на странице «Объекты
сканирования».

v1.6.7: реальный сценарий — родительский домен УЖЕ привязан к объекту
ДО обнаружения поддоменов (иначе разведка поддоменов вообще не
запустится, см. collect_domain_targets/domains_for_target). В этом
случае старая версия sync_bound_domains_to_target синхронизировала
только parent (который уже есть) и реально ничего не добавляла —
именно это и было причиной бага «список доменов не обновляется».

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

    # --- Сценарий 1 (искусственный, как раньше): поддомены без заранее
    # привязанного родителя. ---
    db.add_subdomain(tid, "example.ru", "www.example.ru", ip="10.0.0.1", tool="dnsrecon")
    db.add_subdomain(tid, "example.ru", "mail.example.ru", ip="10.0.0.2", tool="dnsrecon")
    db.add_subdomain(tid, "corp.local", "vpn.corp.local", ip="10.0.0.3", tool="dnsmap")

    chk("до привязки target_domains пуст", db.domains_for_target(tid) == [])

    # Привязать один поддомен → появляется сам FQDN и его родитель.
    db.set_subdomain_bound(tid, "www.example.ru", True)
    added = db.sync_bound_domains_to_target(tid)
    chk("bind_one добавил 2 домена (FQDN + parent)", added == 2)
    chk("www.example.ru в списке доменов объекта",
        "www.example.ru" in db.domains_for_target(tid))
    chk("example.ru (parent) в списке доменов объекта",
        "example.ru" in db.domains_for_target(tid))
    chk("corp.local/vpn.corp.local ещё НЕ добавлены",
        {"corp.local", "vpn.corp.local"}.isdisjoint(db.domains_for_target(tid)))

    # Повторная синхронизация не создаёт дубликатов.
    added2 = db.sync_bound_domains_to_target(tid)
    chk("повторная синхронизация не добавляет дубликатов", added2 == 0)
    chk("www.example.ru встречается один раз",
        db.domains_for_target(tid).count("www.example.ru") == 1)

    # Привязать все новые → появляется второй поддомен + его родитель.
    n = db.set_all_subdomains_bound(tid, True, only_present=True)
    added3 = db.sync_bound_domains_to_target(tid)
    doms = set(db.domains_for_target(tid))
    chk("после bind_all все FQDN и родители присутствуют",
        {"example.ru", "corp.local", "www.example.ru",
         "mail.example.ru", "vpn.corp.local"} <= doms)
    # mail.example.ru (родитель example.ru уже есть) + corp.local + vpn.corp.local = 3
    chk("bind_all добавил ровно 3 новых домена", added3 == 3)

    # list_target_domains должен вернуть эти домены (для index.html).
    ltd = [d["domain"] for d in db.list_target_domains(tid)]
    chk("list_target_domains содержит все домены",
        {"example.ru", "corp.local", "www.example.ru",
         "mail.example.ru", "vpn.corp.local"} <= set(ltd))

    # --- Сценарий 2 (реальный, v1.6.7): родитель уже привязан к объекту
    # ДО обнаружения поддоменов — воспроизводит настоящий баг 1. ---
    tid2 = db.add_target("Тест2", "10.20.30.0/24", "desc2")
    db.add_target_domain(tid2, "acme.test")  # пользователь привязал домен вручную
    chk("acme.test уже в target_domains до разведки",
        "acme.test" in db.domains_for_target(tid2))

    # DNS-разведка нашла новый поддомен под уже привязанным доменом.
    db.add_subdomain(tid2, "acme.test", "host1.acme.test", ip="10.20.30.5", tool="dnsrecon")
    db.set_subdomain_bound(tid2, "host1.acme.test", True)
    added4 = db.sync_bound_domains_to_target(tid2)
    chk("баг 1 воспроизведён и исправлен: FQDN поддомена добавлен "
        "(a не только уже существующий parent)",
        added4 == 1 and "host1.acme.test" in db.domains_for_target(tid2))
    chk("acme.test не задублирован", db.domains_for_target(tid2).count("acme.test") == 1)

    failed = [n for n, ok in checks if not ok]
    print()
    if failed:
        print(f"ПРОВАЛЕНО: {len(failed)} из {len(checks)}")
        sys.exit(1)
    print(f"ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ: {len(checks)}")


if __name__ == "__main__":
    main()
