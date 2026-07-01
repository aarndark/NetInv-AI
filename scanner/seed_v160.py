"""Тестовые данные v1.6.0: модули, ошибки, поддомены, options_full_json —
чтобы проверить рендеринг новых шаблонов (история/текущее/сравнение/поддомены)."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import db

db.init_db()

# Берём существующие main-запуски (после seed_test) объекта id=1.
runs = db.list_runs(target_id=1, scan_class="main", limit=10)
print("main runs:", [r["id"] for r in runs])
if len(runs) >= 2:
    r_new = runs[0]["id"]   # свежий
    r_old = runs[1]["id"]   # предыдущий

    # options_full_json для нового запуска.
    db.set_run_options_full(r_new, json.dumps({
        "syn_mode": "evasion", "profile": "balanced", "top_ports": "1000",
        "extra_nse": True, "do_web": True, "advanced_anp": True,
        "dig_rdns": True, "cve_online": True, "include_info": False,
    }))

    # Модули (graceful degradation) для нового запуска.
    db.set_scan_module(r_new, "nmap", "used")
    db.set_scan_module(r_new, "nse", "used")
    db.set_scan_module(r_new, "whatweb", "used")
    db.set_scan_module(r_new, "nikto", "skipped_missing", "инструмент nikto не установлен")
    db.set_scan_module(r_new, "wpscan", "skipped_missing", "инструмент wpscan не найден в PATH")
    db.set_scan_module(r_new, "dalfox", "skipped_degraded", "пропущен из-за порога Palo Alto")
    db.set_scan_module(r_new, "osv", "used")
    db.set_scan_module(r_new, "dns_recon", "used")

    # Ошибки сканирования (треб. 3): kind=error и kind=degraded.
    db.add_scan_error(r_new, "osv", "OSV API вернул HTTP 400 для запроса версии",
                      "openssl 1.1.1 — некорректный формат PURL", kind="error")
    db.add_scan_error(r_new, "cve_online", "Онлайн-БД CVE недоступна (таймаут NVD)",
                      "connect timeout после 10 c; проверьте сеть/прокси", kind="error")
    db.add_scan_error(r_new, "nikto", "Модуль пропущен (graceful degradation)",
                      "nikto не установлен — установите через apt install nikto", kind="degraded")
    db.add_scan_error(r_new, "parse", "Не удалось разобрать XML nmap для одного хоста",
                      "усечённый вывод; хост пропущен, скан продолжен", kind="error")

    # Поддомены (треб. 5): актуальный, исчезнувший, конфликт.
    db.add_subdomain(1, "example.ru", "www.example.ru", ip="203.0.113.10",
                     tool="dnsrecon", last_run_id=r_new)
    db.add_subdomain(1, "example.ru", "mail.example.ru", ip="203.0.113.11",
                     tool="dnsmap", last_run_id=r_new)
    db.add_subdomain(1, "example.ru", "vpn.example.ru", ip="203.0.113.20",
                     tool="dnsmap", last_run_id=r_old)
    # Конфликт IP: тот же FQDN, разные IP от разных утилит.
    db.add_subdomain(1, "example.ru", "api.example.ru", ip="203.0.113.30",
                     tool="dnsmap", last_run_id=r_new)
    db.add_subdomain(1, "example.ru", "api.example.ru", ip="203.0.113.31",
                     tool="dnsrecon", last_run_id=r_new)
    # Отметим present=1 для поддоменов нового запуска, остальные — исчезнувшие.
    db.mark_subdomains_run(1, r_new)
    print("seed v1.6.0 done: run_new=%s run_old=%s" % (r_new, r_old))
else:
    print("НЕ ХВАТАЕТ main-запусков для сидирования")
