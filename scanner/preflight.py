#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preflight.py — проверка наличия используемых утилит перед сканированием
(требование 6 v1.4.0).

При запуске каждого сканирования NetInv проверяет, какие внешние инструменты
доступны в системе (shutil.which), и формирует сводку «доступно / отсутствует».
Для каждой ОТСУТСТВУЮЩЕЙ утилиты выдаётся конкретная рекомендация по установке
(apt / gem / go), чтобы пользователь мог быстро доустановить недостающее.

ОБЯЗАТЕЛЬНЫЕ инструменты (required=True) — без них основной скан невозможен
(nmap) либо сильно деградирует (curl, dig). ОПЦИОНАЛЬНЫЕ (required=False) —
расширяют покрытие, но их отсутствие НЕ прерывает скан (graceful degradation):
шаг просто пропускается с предупреждением.

Дополнительно проверяется наличие NSE-скрипта vulners (nmap NSE) — он нужен для
онлайн-сопоставления версий ПО с CVE в основном скане (требование 3б).
"""

import os
import shutil
import subprocess

import toolpath  # расширенный поиск утилит (go/bin, snap, /usr/local/bin) — треб. 2 v1.5.0

# Каждая запись: ключ -> словарь с описанием.
#   bin         — имя исполняемого файла для shutil.which;
#   required    — обязателен ли (True) или опционален (False);
#   purpose     — за что отвечает (для сводки, по-русски);
#   install     — команда установки в Kali/Debian.
TOOLS = {
    # --- обязательные ---
    "nmap": {
        "bin": "nmap", "required": True,
        "purpose": "обнаружение узлов, портов, сервисов, NSE",
        "install": "sudo apt install -y nmap",
    },
    "curl": {
        "bin": "curl", "required": True,
        "purpose": "проверка web-ресурсов, заголовков, путей",
        "install": "sudo apt install -y curl",
    },
    "dig": {
        "bin": "dig", "required": True,
        "purpose": "DNS-разведка, обратное разрешение (dig -x)",
        "install": "sudo apt install -y dnsutils",
    },
    # --- опциональные (web-фингерпринт и уязвимости) ---
    "whatweb": {
        "bin": "whatweb", "required": False,
        "purpose": "фингерпринт web-технологий и версий ПО",
        "install": "sudo apt install -y whatweb",
    },
    "nikto": {
        "bin": "nikto", "required": False,
        "purpose": "обзорный web-сканер (только расширенный скан)",
        "install": "sudo apt install -y nikto",
    },
    "wpscan": {
        "bin": "wpscan", "required": False,
        "purpose": "аудит WordPress (только расширенный скан)",
        "install": "sudo gem install wpscan",
    },
    "dalfox": {
        "bin": "dalfox", "required": False,
        "purpose": "лёгкая проверка XSS (только расширенный скан)",
        "install": "go install github.com/hahwul/dalfox/v2@latest",
    },
    # --- опциональные (DNS brute-force поддоменов) ---
    "dnsmap": {
        "bin": "dnsmap", "required": False,
        "purpose": "brute-force поддоменов (DNS-разведка)",
        "install": "sudo apt install -y dnsmap",
    },
    "dnsenum": {
        "bin": "dnsenum", "required": False,
        "purpose": "перечисление поддоменов (DNS-разведка)",
        "install": "sudo apt install -y dnsenum",
    },
    "dnsrecon": {
        "bin": "dnsrecon", "required": False,
        "purpose": "разведка DNS-записей и поддоменов",
        "install": "sudo apt install -y dnsrecon",
    },
}

# NSE-скрипт vulners проверяется отдельно: это не отдельный бинарь, а скрипт
# внутри установки nmap. Нужен для сопоставления версий с CVE (требование 3б).
NSE_VULNERS = "vulners"


def _nmap_has_nse(script_name):
    """Проверить, доступен ли NSE-скрипт указанного имени в установке nmap.

    Сначала ищем файл <script>.nse в стандартных каталогах nmap, затем —
    через `nmap --script-help <script>` (graceful: при любой ошибке → False).
    """
    if not shutil.which("nmap"):
        return False
    # 1) Поиск файла скрипта в типовых каталогах.
    candidates = [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/opt/nmap/share/nmap/scripts",
    ]
    fname = script_name + ".nse"
    for d in candidates:
        try:
            if os.path.isfile(os.path.join(d, fname)):
                return True
        except OSError:
            continue
    # 2) Резервная проверка через --script-help.
    try:
        proc = subprocess.run(
            ["nmap", "--script-help", script_name],
            capture_output=True, text=True, timeout=20)
        out = (proc.stdout or "") + (proc.stderr or "")
        # Если скрипт не найден, nmap пишет "'... matched no scripts'.
        if script_name in out and "matched no scripts" not in out.lower():
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def check_tools():
    """Проверить наличие всех известных утилит.

    Возвращает словарь:
      {
        "available":  [ {key, bin, purpose, required, path}, ... ],
        "missing":    [ {key, bin, purpose, required, install}, ... ],
        "nse_vulners": bool,
        "required_missing": [keys...],   # отсутствующие ОБЯЗАТЕЛЬНЫЕ
      }
    """
    # Требование 2 v1.5.0: добавляем типовые каталоги установки в PATH процесса,
    # чтобы проверка и последующий запуск видели dalfox/snap-утилиты.
    toolpath.augment_path()
    available, missing, required_missing = [], [], []
    for key, meta in TOOLS.items():
        # Ищем через toolpath.which: PATH + ~/go/bin, /root/go/bin, /snap/bin и т.п.
        path = toolpath.which(meta["bin"])
        rec = {
            "key": key,
            "bin": meta["bin"],
            "purpose": meta["purpose"],
            "required": meta["required"],
        }
        if path:
            rec["path"] = path
            available.append(rec)
        else:
            rec["install"] = meta["install"]
            missing.append(rec)
            if meta["required"]:
                required_missing.append(key)
    return {
        "available": available,
        "missing": missing,
        "nse_vulners": _nmap_has_nse(NSE_VULNERS),
        "required_missing": required_missing,
    }


def format_report(result):
    """Сформировать человекочитаемую сводку (список строк, по-русски).

    Подходит и для консоли, и для записи в лог. Включает рекомендации по
    установке для каждой отсутствующей утилиты (требование 6).
    """
    lines = []
    lines.append("Проверка используемых утилит (требование 6):")

    avail = result["available"]
    miss = result["missing"]
    lines.append(f"  Доступно: {len(avail)} / Отсутствует: {len(miss)}")

    if avail:
        lines.append("  Найдены:")
        for r in avail:
            tag = "обязательная" if r["required"] else "опциональная"
            # Показываем путь (треб. 2 v1.5.0): полезно видеть, что dalfox найден
            # например в ~/go/bin, а не в системном PATH.
            where = f"  ({r['path']})" if r.get("path") else ""
            lines.append(f"    [+] {r['bin']:<10} ({tag}) — {r['purpose']}{where}")

    # NSE vulners — отдельной строкой.
    if result["nse_vulners"]:
        lines.append("    [+] nmap NSE vulners — сопоставление версий с CVE доступно")
    else:
        lines.append("    [-] nmap NSE vulners — НЕ найден (offline-таблица CVE "
                     "и онлайн-запрос NVD/OSV продолжат работать)")
        lines.append("        Установка: sudo apt install -y nmap "
                     "(скрипты vulners входят в полную поставку nmap; при "
                     "необходимости обновите базу: nmap --script-updatedb)")

    if miss:
        lines.append("  Отсутствуют (рекомендации по установке):")
        for r in miss:
            tag = "ОБЯЗАТЕЛЬНАЯ" if r["required"] else "опциональная"
            lines.append(f"    [-] {r['bin']:<10} ({tag}) — {r['purpose']}")
            lines.append(f"        Установка: {r['install']}")

    if result["required_missing"]:
        lines.append("  ВНИМАНИЕ: отсутствуют ОБЯЗАТЕЛЬНЫЕ утилиты: "
                     + ", ".join(result["required_missing"])
                     + " — основной скан может не выполниться корректно.")
    else:
        lines.append("  Все обязательные утилиты на месте. Отсутствующие "
                     "опциональные будут аккуратно пропущены (graceful degradation).")
    return lines


def preflight(log=None, detail=None):
    """Выполнить проверку и вывести/залогировать сводку.

    log — функция логирования (например, ScanLogger.log или print). Если None,
    используется print. Возвращает результат check_tools() для дальнейшего
    использования (например, чтобы решить, запускать ли vulners NSE).

    detail (v1.6.4, Правка 3) — callback детального файл-лога: пишет
    полный разбор каждой утилиты (путь/отсутствие/hint) ТОЛЬКО в файл.
    """
    result = check_tools()
    emit = log or print
    for line in format_report(result):
        emit(line)
    if detail:
        detail("=== детальный разбор preflight ===")
        for rec in result.get("available", []):
            detail(f"[+] {rec['key']} ({rec['bin']}): {rec.get('path', '')} "
                   f"— {rec.get('purpose', '')}"
                   + (" [ОБЯЗ.]" if rec.get("required") else ""))
        for rec in result.get("missing", []):
            detail(f"[-] {rec['key']} ({rec['bin']}): ОТСУТСТВУЕТ — "
                   f"{rec.get('purpose', '')}; установка: "
                   f"{rec.get('install', '')}"
                   + (" [ОБЯЗ.]" if rec.get("required") else ""))
        detail(f"nse_vulners доступен: {result.get('nse_vulners')}; "
               f"отсутствуют обязательные: "
               f"{result.get('required_missing') or 'нет'}")
    return result


if __name__ == "__main__":
    preflight(print)
