"""Дополнение к seed_test: добавляет тестовые уязвимости и атрибуты IP,
чтобы визуально проверить новые колонки отчёта (требования 4 и 5).
Запускать ПОСЛЕ seed_test.py."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import db  # noqa: E402

db.init_db()
TARGET_ID = 1

# --- Атрибуты IP (требование 4): Администраторы + флаги контроля и защиты ---
db.set_ip_attributes(TARGET_ID, "192.168.56.10",
                     admins="Иванов И.И. (NOC)",
                     ctrl_cpt=True, ctrl_soc=True, ctrl_vulnscan=True,
                     ctrl_waf=False, ctrl_ddos=True)
db.set_ip_attributes(TARGET_ID, "192.168.56.20",
                     admins="Петров П.П.",
                     ctrl_cpt=True, ctrl_waf=True)

# --- Уязвимости (требование 5) на хостах последнего main-запуска ---
# Находим host_id для нужных IP в последнем main-запуске.
with db.connect() as c:
    run = c.execute(
        "SELECT id FROM scan_runs WHERE target_id=? AND scan_class='main' "
        "ORDER BY id DESC LIMIT 1", (TARGET_ID,)).fetchone()
    run_id = run["id"]
    hmap = {}
    for h in c.execute("SELECT id, ip FROM hosts WHERE run_id=?", (run_id,)):
        hmap[h["ip"]] = h["id"]

h10 = hmap.get("192.168.56.10")
h20 = hmap.get("192.168.56.20")

if h10:
    db.add_vuln(h10, "critical", "secret_file",
                "Открыт каталог .git",
                "GET http://192.168.56.10/.git/HEAD → 200 OK; возможна выгрузка "
                "исходного кода и секретов.",
                "Закрыть доступ к .git на уровне веб-сервера/прокси.",
                "curl", "http://192.168.56.10/",
                severity_reason="Контент подтверждён (сигнатура ref:/HEAD), "
                "не catch-all; раскрытие исходного кода → critical.")
    # Треб. 3б: находка с заполненными CVE-полями (демо блока CVE).
    db.add_vuln(h10, "critical", "cve",
                "Apache httpd 2.4.49 — CVE-2021-41773 (path traversal / RCE)",
                "Server: Apache/2.4.49. Сопоставлено по версии ПО.",
                "Обновите httpd до 2.4.51+; сверьтесь с деталями CVE: "
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "offline-таблица CVE", "http://192.168.56.10/",
                severity_reason="CVSS 7.5 (высокий) → critical; точное совпадение версии.",
                cve_id="CVE-2021-41773", cvss="7.5",
                cve_source="offline-таблица")
    db.add_vuln(h10, "warning", "security_headers",
                "Отсутствует заголовок HSTS",
                "В ответе нет Strict-Transport-Security.",
                "Добавить HSTS на HTTPS-ресурсе.",
                "curl", "https://192.168.56.10/",
                severity_reason="Отсутствие security-заголовка — не прямая компрометация → warning.")
    db.add_vuln(h10, "info", "tech",
                "Обнаружена CMS WordPress",
                "Рекомендуется углублённая проверка wpscan.",
                "Проверить плагины/темы на устаревшие версии.",
                "whatweb", "http://192.168.56.10/")

if h20:
    db.add_vuln(h20, "warning", "open_panel",
                "Открыта админ-панель /admin",
                "GET http://192.168.56.20/admin → 200 OK без авторизации на уровне сети.",
                "Ограничить доступ к панели по IP/VPN.",
                "curl", "http://192.168.56.20/")
    db.add_vuln(h20, "info", "security_headers",
                "Отсутствует X-Content-Type-Options",
                "Нет заголовка X-Content-Type-Options: nosniff.",
                "Добавить заголовок nosniff.",
                "curl", "http://192.168.56.20/")

print("[+] Тестовые уязвимости и атрибуты добавлены.")
print("    h10=%s h20=%s run_id=%s" % (h10, h20, run_id))
