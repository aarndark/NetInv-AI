#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_cron.py — запуск сканирования всех включённых объектов из CLI/cron.

Предназначен для Continuous Penetration Test: ставится в cron/systemd timer и
периодически прогоняет все активные объекты, накапливая историю и отличия.

Пример crontab (каждую ночь в 02:30, профиль stealth под Palo Alto):
    30 2 * * *  cd /opt/netinv && /usr/bin/python3 run_cron.py --profile stealth >> /var/log/netinv.log 2>&1
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner"))
import db        # noqa: E402
import scanner   # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Прогон всех активных объектов (для cron).")
    ap.add_argument("--main", action="store_true",
                    help="ОСНОВНОЙ скан — фиксированный пресет (обход SYN-защиты, "
                         "balanced, NSE, web, alive_no_ports). Остальные опции "
                         "nmap игнорируются. scan_class='main'.")
    ap.add_argument("--profile", default="stealth",
                    choices=list(scanner.TIMING_PROFILES.keys()))
    ap.add_argument("--syn-mode", default="evasion", choices=list(scanner.SYN_MODES),
                    help="evasion = обход SYN-защиты (по умолч.); direct = без обхода")
    ap.add_argument("--top-ports", default=scanner.DEFAULT_TOP_PORTS)
    ap.add_argument("--full-ports", action="store_true")
    ap.add_argument("--extra-nse", action="store_true")
    ap.add_argument("--no-web", action="store_true")
    ap.add_argument("--advanced-anp", action="store_true",
                    help="alive_no_ports advanced check: доп. перепроверка живых "
                         "узлов без открытых портов")
    ap.add_argument("--dig-rdns", action="store_true",
                    help="Обратный DNS: dig -x по каждому найденному IP, "
                         "имя в поле «Доменное имя» (в основном скане всегда вкл.)")
    ap.add_argument("--dns-brute", action="store_true",
                    help="Brute-force перебор поддоменов словарём "
                         "(dnsmap/dnsenum/dnsrecon) для привязанных доменов "
                         "2-го уровня; медленнее, но полнее "
                         "(по умолчанию — быстрый/пассивный режим)")
    args = ap.parse_args()

    db.init_db()
    targets = [t for t in db.list_targets() if t.get("enabled", 1)]
    if not targets:
        print("[!] Нет активных объектов. Добавьте их через web-приложение или CLI.")
        return
    for t in targets:
        cls = "основной" if args.main else "расширенный"
        print(f"[*] === Объект {t['id']}: {t['name']} ({t['cidr']}) | класс: {cls} ===")
        try:
            if args.main:
                # ОСНОВНОЙ скан: фиксированный пресет, scan_class='main'.
                scanner.run_main_scan(t["id"])
            else:
                # РАСШИРЕННЫЙ скан: все параметры из CLI, scan_class='advanced'.
                scanner.run_scan(t["id"], profile=args.profile,
                                 top_ports=args.top_ports, full_ports=args.full_ports,
                                 extra_nse=args.extra_nse, do_web=not args.no_web,
                                 syn_mode=args.syn_mode, advanced_anp=args.advanced_anp,
                                 dig_rdns=args.dig_rdns, dns_brute=args.dns_brute,
                                 scan_class="advanced")
        except Exception as e:  # noqa: BLE001
            print(f"[!] Ошибка по объекту {t['id']}: {e}")


if __name__ == "__main__":
    main()
