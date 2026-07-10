#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner.py — инвентаризационный сканер подсети для Continuous Penetration Test.

ОС: Kali Linux 2026.1. Использует предустановленные инструменты:
    - nmap         (обнаружение узлов, порты, сервисы, NSE)
    - whatweb      (фингерпринт web-технологий)  [опционально]
    - curl         (получение заголовков/титула web-ресурса) [fallback]

УЧЁТ ЗАЩИТЫ PALO ALTO (SYN Flood protection + SYN Cookies)
----------------------------------------------------------
Когда на межсетевом экране Palo Alto включена защита от SYN Flood в режиме
SYN Cookies, firewall сам отвечает SYN-ACK на входящие SYN ДО того, как
соединение реально установлено с защищаемым хостом. Из-за этого классический
SYN-скан (nmap -sS) видит "open" даже на закрытых/недоступных портах — то есть
получает ложноположительные результаты (артефакты SYN-proxy).

Поэтому здесь:
  1. Основной метод — TCP Connect scan (nmap -sT): полное трёхстороннее
     рукопожатие. Порт считается реально открытым, только если хэндшейк
     завершён конечным хостом, а не firewall'ом.
  2. Контроль скорости/таймингов — чтобы НЕ триггерить пороги SYN Flood
     protection зон Palo Alto (alarm/activate/maximal rate). Используются
     --min-rate/--max-rate, -T<n>, --max-retries, --host-timeout, задержки.
  3. Сервисная верификация (-sV + NSE banner/http*) — подтверждает, что за
     портом реально живой сервис (баннер/handshake уровня приложения).
     Порт, открытый по -sT, но БЕЗ подтверждённого сервиса, помечается как
     confidence='syncookie_suspect' (возможный артефакт SYN-cookie proxy).

Скрипт сохраняет результат каждого запуска в SQLite (scanner/db.py) и затем
вызывает diff-движок (scanner/diff_engine.py) для расчёта отличий.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402
import diff_engine  # noqa: E402
import webscan  # noqa: E402
import dns_recon  # noqa: E402
import logsetup  # noqa: E402
import preflight  # noqa: E402
import cve_lookup  # noqa: E402
import errorsink  # noqa: E402
import scancontrol  # noqa: E402
import appversion  # noqa: E402


# Профили таймингов, согласованные с защитой Palo Alto SYN Flood.
# Чем "тише" профиль — тем ниже шанс сработки порогов SYN-flood зон.
TIMING_PROFILES = {
    # Аккуратный режим для боевого периметра за Palo Alto (рекомендуется).
    "stealth": [
        "-T2",
        "--min-rate", "50",
        "--max-rate", "150",
        "--max-retries", "2",
        "--host-timeout", "30m",
        "--scan-delay", "20ms",
    ],
    # Сбалансированный.
    "balanced": [
        "-T3",
        "--min-rate", "150",
        "--max-rate", "400",
        "--max-retries", "2",
        "--host-timeout", "30m",
    ],
    # Быстрый — для лабораторного/доверенного сегмента без жёстких порогов.
    "fast": [
        "-T4",
        "--min-rate", "500",
        "--max-retries", "1",
        "--host-timeout", "20m",
    ],
}

DEFAULT_TOP_PORTS = "1000"

# Фиксированный пресет ОСНОВНОГО сканирования (scan_class='main').
# Пользователь НЕ выбирает параметры основного скана — единственная кнопка
# «Основной скан». Состав пресета (по согласованию):
#   обход SYN-защиты (-sT, evasion) + профиль balanced + расширенный NSE +
#   web-сканирование + alive_no_ports advanced check (в ограниченном режиме,
#   чтобы основной скан не «зависал» на полном -p-).
MAIN_PRESET = {
    "profile": "balanced",
    "syn_mode": "evasion",
    "ports": None,
    "top_ports": DEFAULT_TOP_PORTS,
    "full_ports": False,
    "extra_nse": True,
    "do_web": True,
    "advanced_anp": True,
    "dig_rdns": True,          # обратное разрешение dig -x — всегда в основном скане
    "dns_brute": False,        # brute-force поддоменов — выключен по умолчанию (быстрый режим)
    # CVE-проверки (треб. 3б): В ОСНОВНОМ скане ВКЛЮЧЕНЫ ПО УМОЛЧАНИЮ.
    "cve_online": True,        # онлайн-запрос NVD/OSV по версиям ПО
    "cve_vulners": True,       # nmap NSE vulners по версиям ПО
    # Фильтр находок уровня «инфо» (треб. 6 v1.5.0): в ОСНОВНОМ скане
    # информационные находки НЕ фиксируются (только реальные уязвимости).
    "include_info": False,
}

# Режимы по отношению к защите Palo Alto SYN Flood / SYN Cookies.
#   evasion — режим ОБХОДА: scan спроектирован так, чтобы достоверно работать
#             сквозь SYN-cookie proxy и НЕ триггерить пороги SYN-flood зон.
#             Только TCP Connect (-sT), тихий тайминг, обнаружение узлов через
#             TCP-ACK/SYN-ping (ICMP часто режется), --reason для анализа
#             артефактов SYN-cookie. Достоверность портов подтверждается -sV.
#   direct  — режим БЕЗ ОБХОДА: обычное прямое сканирование без мер уклонения.
#             Использует SYN-скан (-sS, raw-сокеты, нужен root) и стандартный
#             ICMP/обычный host discovery. Быстрее, но за Palo Alto с SYN
#             Cookies даёт ложные "open" и может триггерить защиту — это
#             ожидаемо и оставлено для сравнения/тестов без firewall.
SYN_MODES = ("evasion", "direct")


def which_or_die(tool):
    path = shutil.which(tool)
    if not path:
        sys.stderr.write(f"[!] Не найден инструмент '{tool}'. Установите его в Kali.\n")
    return path


def build_nmap_cmd(target_spec, xml_out, profile="stealth", ports=None,
                   top_ports=DEFAULT_TOP_PORTS, full_ports=False, extra_nse=False,
                   syn_mode="evasion"):
    """
    Сборка команды nmap.

    target_spec — одна или несколько целей через пробел (CIDR плюс
    дополнительные IP, полученные из доменов). nmap принимает
    несколько целей отдельными аргументами.

    syn_mode='evasion' (обход SYN-защиты, по умолчанию):
      -sT  : TCP connect scan — достоверно при SYN Cookies на Palo Alto
      -PS/-PA host discovery вместо ICMP (часто режется firewall'ом)
      тихий профиль таймингов, --reason для анализа SYN-cookie артефактов

    syn_mode='direct' (без обхода):
      -sS  : SYN (half-open) scan, нужен root/CAP_NET_RAW
      -PE  : обычный ICMP echo host discovery
      без мер уклонения — за Palo Alto с SYN Cookies возможны ложные 'open'.
    """
    if syn_mode not in SYN_MODES:
        syn_mode = "evasion"

    if syn_mode == "direct":
        # Прямой SYN-скан без обхода. -sS требует прав raw-сокетов.
        scan_type = ["-sS"]
        discovery = ["-PE", "-PS80,443"]
    else:
        # Режим обхода SYN-защиты: только полное TCP-рукопожатие.
        scan_type = ["-sT"]
        discovery = ["-PS22,80,443,3389,445", "-PA80,443"]

    cmd = ["nmap"] + scan_type + ["-sV", "--version-intensity", "5", "--reason"]
    cmd += discovery

    # Профиль таймингов под защиту SYN Flood
    cmd += TIMING_PROFILES.get(profile, TIMING_PROFILES["stealth"])

    # Диапазон портов
    if ports:
        cmd += ["-p", ports]
    elif full_ports:
        cmd += ["-p-"]
    else:
        cmd += ["--top-ports", str(top_ports)]

    # NSE: безопасные скрипты обнаружения + банеры + базовый http-анализ.
    # default,safe,banner — не эксплойтят, только инвентаризируют.
    scripts = "banner,http-title,http-headers,ssl-cert"
    if extra_nse:
        scripts += ",http-enum,http-methods,ssh-auth-methods,smb-os-discovery"
    cmd += ["--script", scripts]

    # Вывод в XML для надёжного парсинга
    cmd += ["-oX", xml_out]

    # Цели: разбиваем строку по пробелам — nmap принимает несколько целей.
    cmd += str(target_spec).split()
    return cmd


def _strip_nse_scripts(cmd):
    """v1.6.6 (П.1): вернуть команду nmap БЕЗ флага --script и его значения.

    Используется для одноразового повтора после известного сбоя
    планировщика NSE/nsock (assertion 'lua_status(L)==LUA_YIELD' в
    nse_nsock.cc — upstream-баг nmap, см. nmap/nmap#1837, #1906, #3133).
    Все остальные опции (включая -sV) сохраняются без изменений.
    """
    out = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue
        if tok == "--script":
            skip_next = True
            continue
        out.append(tok)
    return out


def parse_nmap_xml(xml_path, syn_mode="evasion"):
    """Парсинг XML-вывода nmap в список хостов с портами и сервисами."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"

        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # Доменное / reverse-DNS имя
        hostname = None
        hn = host.find("hostnames")
        if hn is not None:
            first = hn.find("hostname")
            if first is not None:
                hostname = first.get("name")

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                st = p.find("state")
                pstate = st.get("state") if st is not None else ""
                if "open" not in (pstate or ""):
                    continue
                svc = p.find("service")
                service = product = version = extrainfo = ""
                if svc is not None:
                    service = svc.get("name", "") or ""
                    product = svc.get("product", "") or ""
                    version = svc.get("version", "") or ""
                    extrainfo = svc.get("extrainfo", "") or ""

                # Учёт SYN Cookies: порт "open" с подтверждённым сервисом
                # (есть product/version/banner) считаем confirmed; "open" без
                # признаков живого сервиса — syncookie_suspect.
                reason = st.get("reason", "") if st is not None else ""
                has_service = bool(product or version or
                                   (service and service not in ("tcpwrapped", "unknown")))
                if pstate == "open" and has_service:
                    confidence = "confirmed"
                elif syn_mode == "direct":
                    # Прямой режим без обхода: SYN-cookie артефакты не оцениваем,
                    # порт open считаем как есть (достоверность ниже за firewall).
                    confidence = "confirmed" if pstate == "open" else "filtered"
                elif service == "tcpwrapped":
                    # tcpwrapped часто говорит о SYN-proxy/фильтрации перед хостом
                    confidence = "syncookie_suspect"
                elif pstate == "open":
                    confidence = "syncookie_suspect"
                else:
                    confidence = "filtered"

                ports.append({
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol", "tcp"),
                    "state": pstate,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": (extrainfo + (f" [{reason}]" if reason else "")).strip(),
                    "confidence": confidence,
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "ports": ports,
        })
    return hosts


# --------------------------------------------------------------------------
# Обратное разрешение IP -> доменное имя через dig -x
# --------------------------------------------------------------------------
# Тайм-аут одного dig-запроса (DNS обычно отвечает быстро; страхуемся).
DIG_TIMEOUT = 8


def dig_reverse(ip):
    """Обратное разрешение IP в доменное имя командой `dig -x <IP>`.

    Возвращает PTR-имя (без завершающей точки) либо None, если запись
    отсутствует/dig недоступен/таймаут. Используется для заполнения поля
    «Доменное имя» (всегда в основном скане, по опции — в расширенном).
    """
    if not shutil.which("dig"):
        return None
    # +short — только сам ответ (PTR-имена), без служебной информации.
    cmd = ["dig", "-x", ip, "+short", f"+time={DIG_TIMEOUT}", "+tries=1"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=DIG_TIMEOUT + 2)
    except subprocess.TimeoutExpired:
        return None
    except Exception:  # noqa: BLE001
        return None
    if proc.returncode != 0:
        return None
    # +short может вернуть несколько строк (цепочка CNAME/PTR). Берём первую
    # непустую запись, отбрасываем завершающую точку FQDN.
    for line in proc.stdout.splitlines():
        name = line.strip().rstrip(".")
        if name:
            return name
    return None


# --------------------------------------------------------------------------
# Углублённая перепроверка узлов alive_no_ports
# --------------------------------------------------------------------------
# Узел alive_no_ports — это IP, который ответил на host discovery ("живой"),
# но при основном скане НИ ОДИН открытый TCP-порт не подтверждён. Причины
# (см. README, раздел "Устранение неполадок"): фантом SYN-cookie proxy на
# Palo Alto, сервис вне top-1000, UDP-only сервис, фильтрация портов и т.п.
#
# По галочке "alive_no_ports advanced check" такие IP перепроверяются тремя
# командами nmap и для каждого формируется текстовое пояснение.

# Тайм-аут одной advanced-команды (полный диапазон портов может идти долго).
ADV_FULL_TIMEOUT = 60 * 60          # nmap -p- (все 65535)
ADV_REASON_TIMEOUT = 60 * 5         # точечные 4 порта с --reason
ADV_UDP_TIMEOUT = 60 * 15           # top-50 UDP

# В ОСНОВНОМ скане полный -p- по каждому alive_no_ports-узлу может занимать
# десятки минут и «вешать» весь прогон. Поэтому для основного скана advanced
# check выполняется в ОГРАНИЧЕННОМ (bounded) режиме: вместо -p- берём top-3000
# портов с укороченным таймаутом. Расширенный скан, выбранный вручную, при
# advanced-anp выполняет полный -p- как раньше.
ADV_BOUNDED_TIMEOUT = 60 * 6        # ограниченный TCP-проход (top-3000)
ADV_BOUNDED_TOP_PORTS = "3000"


def _run_nmap_xml(cmd, timeout):
    """Запустить nmap с -oX во временный файл, вернуть (распарсенные хосты, ошибка)."""
    fd, xml_out = tempfile.mkstemp(suffix=".xml", prefix="nmap_adv_")
    os.close(fd)
    cmd = list(cmd) + ["-oX", xml_out]
    err = None
    parsed = []
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0:
            parsed = parse_nmap_xml(xml_out, syn_mode="direct")
    except subprocess.TimeoutExpired:
        err = "превышен таймаут"
    except Exception as e:  # noqa: BLE001
        err = str(e)
    finally:
        try:
            os.remove(xml_out)
        except OSError:
            pass
    return parsed, err


def _udp_open_probe(ip):
    """Требование 9: nmap -sU -Pn --top-ports 50 --reason -vv <IP>.

    Возвращает список UDP-портов, ТОЧНО находящихся в состоянии 'open'
    (НЕ 'open|filtered'). Разбираем XML отдельно, потому что в основной
    парсер попадают и 'open|filtered' (любое state, содержащее 'open').
    """
    fd, xml_out = tempfile.mkstemp(suffix=".xml", prefix="nmap_udp_")
    os.close(fd)
    cmd = ["nmap", "-sU", "-Pn", "--top-ports", "50", "--reason", "-vv",
           ip, "-oX", xml_out]
    open_ports = []
    err = None
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=ADV_UDP_TIMEOUT)
        if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0:
            tree = ET.parse(xml_out)
            for host in tree.getroot().findall("host"):
                pel = host.find("ports")
                if pel is None:
                    continue
                for p in pel.findall("port"):
                    if p.get("protocol") != "udp":
                        continue
                    st = p.find("state")
                    # Считаем открытыми ТОЛЬКО state == 'open'
                    # (исключаем 'open|filtered' и пр.).
                    if st is not None and st.get("state") == "open":
                        open_ports.append(int(p.get("portid")))
    except subprocess.TimeoutExpired:
        err = "превышен таймаут"
    except Exception as e:  # noqa: BLE001
        err = str(e)
    finally:
        try:
            os.remove(xml_out)
        except OSError:
            pass
    return sorted(set(open_ports)), err


def advanced_check_alive_no_ports(ip, bounded=False):
    """Углублённая перепроверка одного alive_no_ports-узла.

    Выполняет три проверки:
        1) TCP-диапазон:
             - полный (-p-) для расширенного скана;
             - ОГРАНИЧЕННЫЙ (--top-ports 3000) для основного скана
               (bounded=True), чтобы основной прогон не «зависал».
        2) nmap -sT -Pn --reason -p 80,443,22,3389 <IP>
           — различить closed (RST) от filtered (режет firewall)
        3) nmap -sU -Pn --top-ports 50 --reason -vv <IP>  (требование 9)
           — UDP-сервисы; открытыми считаются только порты state='open'.

    Возвращает человекочитаемое пояснение (русский) с интерпретацией.
    """
    notes = []
    found_tcp = []
    found_udp = []

    # --- 1) TCP-диапазон --------------------------------------------------
    if bounded:
        cmd1 = ["nmap", "-sT", "-Pn", "--top-ports", ADV_BOUNDED_TOP_PORTS,
                "--max-retries", "2", "--scan-delay", "20ms", ip]
        tcp_label = f"top-{ADV_BOUNDED_TOP_PORTS}"
        tcp_timeout = ADV_BOUNDED_TIMEOUT
    else:
        cmd1 = ["nmap", "-sT", "-Pn", "-p-", "--max-retries", "2",
                "--scan-delay", "30ms", ip]
        tcp_label = "-p- (1-65535)"
        tcp_timeout = ADV_FULL_TIMEOUT
    p1, e1 = _run_nmap_xml(cmd1, tcp_timeout)
    if e1:
        notes.append(f"[TCP {tcp_label}] ошибка/таймаут: {e1}")
    else:
        for h in p1:
            for prt in h.get("ports", []):
                found_tcp.append(prt["port"])
        if found_tcp:
            plist = ", ".join(str(x) for x in sorted(set(found_tcp)))
            notes.append(f"[TCP {tcp_label}] обнаружены открытые порты вне top-1000: {plist}")
        else:
            notes.append(f"[TCP {tcp_label}] открытых TCP-портов не найдено")

    # --- 2) точечный --reason на ключевых портах ----------------------
    # Здесь нас интересует не столько open, сколько closed vs filtered,
    # поэтому разбираем XML отдельно (по всем state, не только open).
    reason_summary = _reason_probe(ip)
    if reason_summary:
        notes.append(reason_summary)

    # --- 3) UDP top-50 (требование 9) -------------------------------------
    # -sU требует root; если прав нет — nmap сообщит об этом.
    # Открытыми считаем ТОЛЬКО порты в состоянии 'open'.
    found_udp, e3 = _udp_open_probe(ip)
    if e3:
        notes.append(f"[UDP top-50] ошибка/таймаут: {e3} (возможно, нужен root)")
    elif found_udp:
        ulist = ", ".join(str(x) for x in found_udp)
        notes.append(f"[UDP top-50 --reason] открытые (state=open) UDP-порты: {ulist}")
    else:
        notes.append("[UDP top-50 --reason] открытых (state=open) UDP-портов не найдено")

    # --- Итоговая интерпретация -----------------------------------------
    verdict = _interpret_advanced(found_tcp, found_udp, reason_summary)
    note = "ВЫВОД: " + verdict + "\n" + "\n".join(notes)
    return note


def _reason_probe(ip):
    """nmap -sT -Pn --reason -p 80,443,22,3389: сводка closed/filtered/open."""
    fd, xml_out = tempfile.mkstemp(suffix=".xml", prefix="nmap_reason_")
    os.close(fd)
    cmd = ["nmap", "-sT", "-Pn", "--reason", "-p", "80,443,22,3389", ip, "-oX", xml_out]
    states = {}
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=ADV_REASON_TIMEOUT)
        if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0:
            tree = ET.parse(xml_out)
            for host in tree.getroot().findall("host"):
                pel = host.find("ports")
                if pel is None:
                    continue
                for p in pel.findall("port"):
                    st = p.find("state")
                    if st is None:
                        continue
                    portid = p.get("portid")
                    states[portid] = (st.get("state", ""), st.get("reason", ""))
    except subprocess.TimeoutExpired:
        return "[--reason] превышен таймаут"
    except Exception as e:  # noqa: BLE001
        return f"[--reason] ошибка: {e}"
    finally:
        try:
            os.remove(xml_out)
        except OSError:
            pass
    if not states:
        return "[--reason] нет данных по портам 80/443/22/3389"
    parts = [f"{pid}={stt}({rsn})" for pid, (stt, rsn) in sorted(states.items())]
    return "[--reason 80,443,22,3389] " + ", ".join(parts)


def _interpret_advanced(found_tcp, found_udp, reason_summary):
    """Сформировать короткий вердикт по результатам трёх проверок."""
    rs = reason_summary or ""
    has_filtered = "filtered" in rs
    has_closed = "closed" in rs
    if found_tcp:
        return ("узел реально живой, сервис(ы) работают на нестандартных портах "
                "вне top-1000 — рекомендуется добавить эти порты в регулярный скан")
    if found_udp:
        return ("TCP-сервисов нет, но обнаружены UDP-сервисы — узел живой и предоставляет "
                "сервисы по UDP (основной TCP Connect их не видит)")
    if has_closed and not has_filtered:
        return ("узел реально живой, порты отвечают RST (closed) — это настоящий хост "
                "без публичных сервисов в проверенном диапазоне")
    if has_filtered and not has_closed:
        return ("пакеты режет firewall (filtered) — вероятно влияние SYN-защиты Palo Alto; "
                "повторите скан с более мягким таймингом либо сравните с режимом direct")
    if has_filtered and has_closed:
        return ("часть портов closed, часть filtered — хост живой, но периметр частично "
                "фильтруется firewall'ом")
    return ("открытых портов не подтверждено ни TCP, ни UDP; при отсутствии отклика на "
            "портах вероятен фантомный адрес от SYN-cookie proxy (Palo Alto отвечает "
            "за защищаемый IP) либо хост доступен только изнутри сегмента")


def _build_options_json(syn_mode, profile, ports, top_ports, full_ports,
                        extra_nse, do_web, advanced_anp, dig_rdns=False,
                        dns_brute=False):
    """Краткие опции расширенного запуска для истории (требование 12)."""
    if ports:
        ports_label = ports
    elif full_ports:
        ports_label = "все (-p-)"
    else:
        ports_label = f"top-{top_ports}"
    return json.dumps({
        "syn_mode": syn_mode,            # evasion=обход SYN-защиты / direct
        "profile": profile,             # stealth/balanced/fast
        "ports": ports_label,
        "extra_nse": bool(extra_nse),
        "do_web": bool(do_web),
        "advanced_anp": bool(advanced_anp),
        "dig_rdns": bool(dig_rdns),       # обратное разрешение dig -x
        "dns_brute": bool(dns_brute),     # brute-force поиск поддоменов
    }, ensure_ascii=False)


def _finalize_cancelled(run_id, slog, log, target_id, scan_class, phases=None):
    """v1.6.1 (правка 1): корректно завершить прерванный оператором скан.

    Помечает запуск статусом «cancelled», фиксирует уже собранные узлы
    через пересчёт состояний и закрывает подробный лог. Возвращает run_id.

    phases (v1.6.6, П.1): уже накопленный пофазовый статус (dns/nmap/webscan);
    оставшиеся незаданные этапы подписываются как «skipped» (отменено до
    их наступления).
    """
    finished = dt.datetime.now().isoformat(timespec="seconds")
    try:
        log("[!] Сканирование отменено оператором.")
    except Exception:  # noqa: BLE001
        pass
    # v1.6.3: завершаем фазу CVE — сбрасываем состояние онлайн-источника.
    try:
        cve_lookup.online_teardown(log=log)
    except Exception:  # noqa: BLE001
        pass
    # v1.6.6 (П.1): дописываем незаданные этапы как skipped и сохраняем.
    try:
        p = dict(phases or {})
        for k in ("dns", "nmap", "webscan"):
            p.setdefault(k, "skipped")
        db.set_run_phases_json(run_id, json.dumps(p, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass
    try:
        db.finish_run(run_id, "cancelled", finished, 0,
                      "Сканирование отменено оператором.")
    except Exception:  # noqa: BLE001
        pass
    # Пересчитываем состояния по уже сохранённым узлам (если были).
    try:
        diff_engine.update_host_states(target_id, run_id, scan_class=scan_class)
    except Exception:  # noqa: BLE001
        pass
    try:
        slog.section("✗ Сканирование ОТМЕНЕНО оператором")
        slog.close()
    except Exception:  # noqa: BLE001
        pass
    return run_id


def run_main_scan(target_id, dry_run=False, control=None):
    """ОСНОВНОЙ скан — фиксированный пресет (MAIN_PRESET, scan_class='main')."""
    return run_scan(target_id, scan_class="main", dry_run=dry_run,
                    control=control, **MAIN_PRESET)


def collect_domain_targets(target_id, dns_brute=False, log=None, sink=None,
                           detail=None):
    """Разведка всех доменов, привязанных к объекту.

    Для каждого домена:
      * домен 2-го уровня  → поиск поддоменов (dnsmap/dnsenum/dnsrecon) + резолв;
      * домен 3+ уровня → только резолв IP.

    Возвращает: (extra_ips, ip_sources, fqdn_by_ip, recon_log)
      extra_ips   — отсортированный список уникальных IP из доменов;
      ip_sources  — {ip: (source, domain)} для записи происхождения;
      fqdn_by_ip  — {ip: fqdn} для обогащения «Доменного имени»;
      recon_log   — строки журнала разведки.
    Найденные поддомены сохраняются в БД (discovered_subdomains).
    """
    recon_log = []

    def _log(msg):
        recon_log.append(str(msg))
        if log:
            log(msg)

    domains = db.domains_for_target(target_id)
    extra_ips = set()
    ip_sources = {}     # ip -> (source, domain)
    fqdn_by_ip = {}     # ip -> fqdn
    if not domains:
        return [], ip_sources, fqdn_by_ip, recon_log

    _log(f"[dns] Привязано доменов: {len(domains)} — {', '.join(domains)}")
    for domain in domains:
        res = dns_recon.recon_domain(domain, brute=dns_brute, log=_log,
                                     detail=detail)
        lvl = "2-й уровень (apex)" if res["is_apex"] else f"{res['level']}-й уровень"
        _log(f"[dns] {domain}: {lvl}, IP найдено {len(res['ips'])}, "
             f"поддоменов {len(res['subdomains'])}")
        if res["tools_missing"]:
            _log(f"[dns] {domain}: не найдены утилиты: "
                 f"{', '.join(res['tools_missing'])}")
            # Треб. 2/3: фиксируем graceful degradation DNS-разведки
            # (какие утилиты отсутствуют) — как «мягкую» запись в ошибках.
            if sink is not None:
                sink.degraded(
                    "dns_recon",
                    f"{domain}: не найдены утилиты DNS-разведки: "
                    f"{', '.join(res['tools_missing'])} (пропущены)")
        # IP самого домена и поддоменов.
        for ip, source in res["ips"].items():
            extra_ips.add(ip)
            # Не понижаем domain до subdomain, если IP уже встречался как domain.
            if ip not in ip_sources or source == "domain":
                ip_sources[ip] = (source, domain)
        for ip, fqdn in res["fqdn_by_ip"].items():
            fqdn_by_ip.setdefault(ip, fqdn)
        # Сохраняем найденные поддомены (v1.6.4 — с признаком артефакта).
        n_artifacts = 0
        for s in res["subdomains"]:
            art = int(s.get("is_artifact") or 0)
            n_artifacts += art
            db.add_subdomain(target_id, s["parent"], s["subdomain"],
                             ip=s.get("ip"), tool=s.get("tool"),
                             is_artifact=art,
                             verify_reason=s.get("verify_reason"))
        if n_artifacts:
            _log(f"[dns] {domain}: артефактов обнаружения отмечено {n_artifacts} "
                 f"(не прошли проверку соответствия IP — смещены вниз, "
                 f"исключены из «Привязать все новые»)")

    return sorted(extra_ips), ip_sources, fqdn_by_ip, recon_log


def run_scan(target_id, profile="stealth", ports=None, top_ports=DEFAULT_TOP_PORTS,
             full_ports=False, extra_nse=False, do_web=True, dry_run=False,
             syn_mode="evasion", advanced_anp=False, scan_class="advanced",
             dig_rdns=False, dns_brute=False, cve_online=True, cve_vulners=True,
             include_info=False, control=None):
    """Полный цикл: nmap -> парсинг -> сохранение -> web-сканирование -> diff.

    scan_class: 'main' (основной, фиксированный пресет) либо 'advanced'
    (расширенный). Статистика и «Отличия» ведутся ОТДЕЛЬНО по классу.

    dns_brute: включить brute-force перебор поддоменов (медленнее, полнее).

    include_info (треб. 6 v1.5.0): фиксировать ли находки уровня «инфо».
    По умолчанию False — информационные находки НЕ сохраняются в БД
    (в ОСНОВНОМ скане и без галочки в расширенном). При True фиксируются все.
    """
    # v1.6.1 (правка 1): точка контроля паузы/отмены между этапами.
    def _ck():
        if control is not None:
            control.checkpoint()

    # П.3 (v1.6.5): пометить фазу скана (для полосы прогресса в «Текущем»).
    def _phase(name):
        if control is not None:
            control.set_phase(name)

    # Нормализуем имя уровня «инфо» для фильтрации (треб. 6).
    _INFO_SEVERITIES = {"info", "инфо", "informational"}
    # v1.6.6 (П.1): пофазовый статус запуска (dns/nmap/webscan ->
    # ok|failed|skipped|off) для колонки «Ошибки сканирования» истории.
    phases = {}
    nmap_crash_retried = False
    db.init_db()
    target = db.get_target(target_id)
    if not target:
        raise SystemExit(f"target_id={target_id} не найден")

    # —— Ранняя инициализация подробного лога (треб. 5) ——
    # Весь ход скана пишется в netinv_YYMMDD_TIME.log и дублируется в консоль.
    slog = logsetup.ScanLogger(run_id=None, echo_console=True)

    # —— Коллектор ошибок и статусов модулей (v1.6.0, треб. 2, 3) ——
    # Буферизует всё до появления run_id, затем сбрасывает в БД. Ошибки
    # инструментов, проходящие через log(), перехватываются по шаблонам.
    sink = errorsink.ErrorSink()

    def log(msg):
        """Единая точка логирования: в файл лога + консоль (треб. 5, 7).
        Дополнительно распознаёт ОЧЕВИДНЫЕ ошибки инструментов и дублирует
        их в scan_errors (треб. 3) — недоступность OSV, HTTP 400, сбои
        парсинга и т.п. Результаты скана (недоступность хостов) НЕ ловятся."""
        slog.log(msg)
        sink.scan_log_line(msg)

    # —— Детальные sink-и для файл-лога (v1.6.4, Правка 3) ——
    # Пишут сырой/подробный вывод МОДУЛЕЙ ТОЛЬКО в файл (DEBUG),
    # не зашумляя консоль. Раньше детально писался только nmap.
    detail_web = slog.make_detail_sink("webscan")
    detail_cve = slog.make_detail_sink("cve")
    detail_dns = slog.make_detail_sink("dns")
    detail_pre = slog.make_detail_sink("preflight")

    slog.section(f"НАЧАЛО СКАНИРОВАНИЯ: {target['name']} ({target['cidr']})")
    log(f"Класс скана: {scan_class}; режим SYN: {syn_mode}; профиль: {profile}")

    # —— Проверка наличия утилит (треб. 6) ——
    slog.section("ПРОВЕРКА УТИЛИТ (треб. 6)")
    pf = preflight.preflight(log=log, detail=detail_pre)
    # Базовые модули: nmap всегда применяется (без него скан падает).
    sink.module("nmap", errorsink.STATUS_USED)
    sink.module("nse", errorsink.STATUS_USED if extra_nse
                else errorsink.STATUS_OFF,
                None if extra_nse else "NSE-скрипты отключены опциями")
    sink.module("cve_offline", errorsink.STATUS_USED)
    # Если nmap NSE vulners не найден — отключаем vulners (graceful), CVE
    # продолжают работать через offline-таблицу и онлайн NVD/OSV.
    if not cve_vulners:
        sink.module("nse_vulners", errorsink.STATUS_OFF,
                    "vulners отключён опциями запуска")
    elif not pf.get("nse_vulners"):
        msg = ("nmap NSE vulners не обнаружен — сопоставление CVE через "
               "vulners пропущено (offline-таблица и онлайн NVD/OSV работают)")
        log(msg)
        sink.module("nse_vulners", errorsink.STATUS_SKIPPED_MISSING,
                    "NSE-скрипт vulners не установлен")
        cve_vulners = False
    else:
        sink.module("nse_vulners", errorsink.STATUS_USED)

    # Однократная проверка доступности OSV при запуске (треб. 5 v1.5.0).
    # Делается ОДИН раз за скан, чтобы в терминал не сыпались однотипные
    # ошибки «Connection refused» на каждый продукт. Если CIRCL недоступен,
    # онлайн-запросы пропускаются, работает offline-таблица (graceful).
    if cve_online:
        online_ok = cve_lookup.online_healthcheck(log=log)
        if online_ok:
            sink.module("cve_online", errorsink.STATUS_USED)
        else:
            # Ошибка недоступности уже зафиксирована через log() → sink.
            sink.module("cve_online", errorsink.STATUS_SKIPPED_DEGRADED,
                        "cve.circl.lu недоступен (нет выхода в Интернет)")
    else:
        sink.module("cve_online", errorsink.STATUS_OFF,
                    "онлайн-CVE отключён опциями запуска")

    started = dt.datetime.now().isoformat(timespec="seconds")
    xml_fd, xml_out = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
    os.close(xml_fd)

    # —— DNS-разведка доменов объекта (до запуска nmap) ——
    # Собираем IP из привязанных доменов и добавляем их к сканированию.
    _phase(scancontrol.PHASE_DNS)  # П.3: фаза DNS-разведки
    slog.section("DNS-РАЗВЕДКА ДОМЕНОВ")
    extra_ips, ip_sources, fqdn_by_ip, recon_log = collect_domain_targets(
        target_id, dns_brute=dns_brute, log=log, sink=sink, detail=detail_dns)
    # Статусы DNS-модулей (треб. 2). Если доменов нет — DNS-разведка
    # не выполнялась (нечего разведывать).
    # v1.6.6 (П.1): фаза dns для колонки «Ошибки сканирования» —
    # "off", если у объекта нет доменов (нечего разведывать).
    phases["dns"] = "ok" if db.domains_for_target(target_id) else "off"
    if db.domains_for_target(target_id):
        sink.module("dns_recon", errorsink.STATUS_USED)
        sink.module("dns_brute", errorsink.STATUS_USED if dns_brute
                    else errorsink.STATUS_OFF,
                    None if dns_brute else "brute-force поддоменов отключён")
    sink.module("dig_rdns", errorsink.STATUS_USED if dig_rdns
                else errorsink.STATUS_OFF,
                None if dig_rdns else "обратный DNS отключён опциями")
    sink.module("webscan", errorsink.STATUS_USED if do_web
                else errorsink.STATUS_OFF,
                None if do_web else "web-проверка отключена опциями")
    # Тяжёлые web-инструменты запускаются только в расширенном скане
    # (чтобы не триггерить пороги Palo Alto в основном).
    if do_web and scan_class != "advanced":
        for _m in ("nikto", "wpscan", "dalfox"):
            sink.module(_m, errorsink.STATUS_OFF,
                        "тяжёлые проверки отключены в основном скане (Palo Alto)")
    # Множество внешних IP (из DNS-обогащения) — НЕ за Palo Alto (треб. 2).
    external_ips = set(extra_ips)

    # Происхождение всех IP из CIDR помечаем как 'cidr' (не понижая именованные).
    # IP из доменов — с их источником (domain|subdomain).
    for ip, (source, domain) in ip_sources.items():
        db.set_ip_origin(target_id, ip, source, domain)

    # Цели nmap = CIDR + дополнительные IP из доменов (без дубликатов-строк).
    target_spec = target["cidr"]
    if extra_ips:
        target_spec = target_spec + " " + " ".join(extra_ips)
        log(f"[*] Добавлено внешних IP из доменов (ВНЕ периметра Palo Alto): "
            f"{len(extra_ips)} — {', '.join(extra_ips)}")
        log("[*] Для этих IP НЕ учитывается SYN-flood/SYN-cookie защита (треб. 2): "
            "открытый порт = подтверждён, web-проверка углублённая.")

    cmd = build_nmap_cmd(target_spec, xml_out, profile, ports,
                         top_ports, full_ports, extra_nse, syn_mode)
    cmd_str = " ".join(cmd)
    # Краткие опции сохраняем только для расширенного скана (старая история).
    options_json = None
    if scan_class == "advanced":
        options_json = _build_options_json(syn_mode, profile, ports, top_ports,
                                           full_ports, extra_nse, do_web, advanced_anp,
                                           dig_rdns=dig_rdns, dns_brute=dns_brute)
    # v1.6.0 (треб. 2): полный набор опций — для ОБОИХ классов (раскрывающийся
    # список «опции»: обход SYN-защиты, обратный DNS и прочее).
    options_full_json = _build_options_json(
        syn_mode, profile, ports, top_ports, full_ports, extra_nse, do_web,
        advanced_anp, dig_rdns=dig_rdns, dns_brute=dns_brute)
    run_id = db.create_run(target_id, started, f"{profile}/{syn_mode}", cmd_str,
                           scan_class=scan_class, options_json=options_json,
                           options_full_json=options_full_json)
    # Привязываем run_id к логу (имя логгера уже создано; работаем дальше).
    slog.run_id = run_id
    # v1.6.0 (треб. 4): сохраняем путь к файлу лога для «ссылки на лог».
    try:
        db.set_run_log_path(run_id, slog.path)
    except Exception:  # noqa: BLE001
        pass
    # v1.6.0 (треб. 2, 3): сбрасываем накопленные ошибки/статусы модулей
    # в БД (до этого run_id не существовал) + сохраняем modules_json.
    sink.bind_run(run_id)
    db.set_run_modules_json(run_id, sink.modules_json())
    # Отмечаем присутствие поддоменов в этом запуске (треб. 5): те, что
    # обнаружены сейчас — present=1, остальные — present=0 («исчезли»).
    # add_subdomain в разведке вызывался без run_id — проставляем его теперь
    # по времени старта (разведка шла после started).
    db.mark_subdomains_run(target_id, run_id, since=started)
    # v1.6.1 (правка 3): конфликты IP разрешаются АВТОМАТИЧЕСКИ —
    # каждый поддомен остаётся в таблице одной строкой с актуальным IP.
    n_res = db.auto_resolve_subdomains(target_id)
    if n_res:
        log(f"[*] Поддомены: автоматически разрешено конфликтов IP: {n_res}")
    log(f"[*] Запуск #{run_id} для {target['name']} ({target['cidr']})")
    log(f"[*] Команда nmap: {cmd_str}")

    if dry_run:
        log("[dry-run] nmap не запускается, выводится только командная строка.")
        # v1.6.6 (П.1): dry-run — nmap/web фактически не выполнялись.
        phases["nmap"] = "off"
        phases["webscan"] = "off"
        try:
            db.set_run_phases_json(run_id, json.dumps(phases, ensure_ascii=False))
        except Exception:  # noqa: BLE001
            pass
        db.finish_run(run_id, "done", dt.datetime.now().isoformat(timespec="seconds"),
                      0, "dry-run")
        diff_engine.update_host_states(target_id, run_id, scan_class=scan_class)
        cve_lookup.online_teardown(log=log)   # v1.6.3: завершаем фазу CVE
        slog.close()
        return run_id

    if not which_or_die("nmap"):
        # v1.6.6 (П.1): nmap не найден — фаза nmap провалена, web пропущен.
        phases["nmap"] = "failed"
        phases["webscan"] = "skipped"
        try:
            db.set_run_phases_json(run_id, json.dumps(phases, ensure_ascii=False))
        except Exception:  # noqa: BLE001
            pass
        db.finish_run(run_id, "error",
                      dt.datetime.now().isoformat(timespec="seconds"), 0,
                      "nmap не установлен")
        cve_lookup.online_teardown(log=log)   # v1.6.3: завершаем фазу CVE
        slog.close()
        raise SystemExit("nmap отсутствует")

    log_lines = []
    # v1.6.1 (правка 1): проверка паузы/отмены перед запуском nmap.
    try:
        _ck()
    except scancontrol.ScanCancelled:
        return _finalize_cancelled(run_id, slog, log, target_id, scan_class, phases)
    # Треб. 7: запуск nmap с ПОТОКОВЫМ выводом в консоль и лог.
    _phase(scancontrol.PHASE_NMAP)  # П.3: фаза nmap-сканирования
    slog.section("ЗАПУСК NMAP (потоковый вывод, треб. 7)")
    try:
        # Добавляем --stats-every для периодического прогресса в реальном времени.
        stream_cmd = cmd + ["--stats-every", "10s"]
        proc = logsetup.run_streamed(stream_cmd, timeout=60 * 90, slog=slog,
                                     label="nmap", control=control)
        log_lines.append((proc.stdout or "")[-4000:])
        if proc.returncode != 0:
            log_lines.append(f"nmap завершился с кодом {proc.returncode}")
        # v1.6.6 (П.1): известный сбой планировщика NSE/nsock — nmap
        # аварийно завершается сигналом (assertion 'lua_status(L)==LUA_YIELD'
        # в nse_nsock.cc, см. upstream nmap/nmap#1837, #1906, #3133). subprocess
        # возвращает отрицательный returncode, если процесс убит сигналом.
        # Не фатально — повторяем ту же команду без --script.
        if proc.returncode is not None and proc.returncode < 0:
            sig = -proc.returncode
            emsg = (f"nmap аварийно завершён сигналом {sig} — известный сбой "
                    "планировщика NSE/nsock (nse_nsock.cc, assertion "
                    "lua_status(L)==LUA_YIELD). Повтор без NSE-скриптов...")
            log(emsg)
            sink.error("nmap", emsg, kind="error")
            nmap_crash_retried = True
            try:
                os.remove(xml_out)
            except OSError:
                pass
            retry_cmd = _strip_nse_scripts(cmd) + ["--stats-every", "10s"]
            log(f"[*] Повтор команды nmap (без --script): {' '.join(retry_cmd)}")
            proc = logsetup.run_streamed(retry_cmd, timeout=60 * 90, slog=slog,
                                         label="nmap-retry", control=control)
            log_lines.append((proc.stdout or "")[-4000:])
            if proc.returncode != 0:
                log_lines.append(f"nmap (повтор без NSE) завершился с кодом {proc.returncode}")
            if proc.returncode is not None and proc.returncode < 0:
                emsg2 = ("Повторный запуск nmap без NSE-скриптов также аварийно "
                        f"завершён сигналом {-proc.returncode}.")
                log(emsg2)
                sink.error("nmap", emsg2, kind="error")
            else:
                log("[*] Повтор без NSE-скриптов выполнен без сбоя.")
    except subprocess.TimeoutExpired:
        log_lines.append("nmap: превышен общий таймаут")
    except Exception as e:  # noqa: BLE001
        # v1.6.6 (П.1): фатальный сбой nmap — фаза nmap провалена, web не выполнялся.
        phases["nmap"] = "failed"
        phases["webscan"] = "off" if not do_web else "skipped"
        try:
            db.set_run_phases_json(run_id, json.dumps(phases, ensure_ascii=False))
        except Exception:  # noqa: BLE001
            pass
        db.finish_run(run_id, "error",
                      dt.datetime.now().isoformat(timespec="seconds"), 0, str(e))
        cve_lookup.online_teardown(log=log)   # v1.6.3: завершаем фазу CVE
        slog.close()
        raise

    # v1.6.1 (правка 1): проверка отмены после nmap, до тяжёлой
    # постобработки (парсинг XML, web-скан, CVE, diff).
    try:
        _ck()
    except scancontrol.ScanCancelled:
        return _finalize_cancelled(run_id, slog, log, target_id, scan_class, phases)

    hosts_up = 0
    # v1.6.6 (П.1): флаг успешного парсинга XML nmap — основа итогового
    # статуса фазы nmap в колонке «Ошибки сканирования».
    nmap_parse_ok = False
    if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0:
        try:
            parsed = parse_nmap_xml(xml_out, syn_mode)
            nmap_parse_ok = True
        except ET.ParseError as e:
            parsed = []
            # Через log() — чтобы попало в scan_errors (треб. 3, перехват parse).
            emsg = f"Ошибка парсинга XML: {e}"
            log(emsg)
            log_lines.append(emsg)

        anp_hosts = []  # (host_id, ip) узлов alive_no_ports для advanced-проверки
        if do_web:
            _phase(scancontrol.PHASE_WEB)  # П.3: фаза web-проверок
        for h in parsed:
            # v1.6.1 (правка 1): отмена в ходе web/CVE-обработки узлов —
            # прерываем цикл между узлами, уже сохранённые данные остаются.
            if control is not None and control.is_cancelled():
                return _finalize_cancelled(run_id, slog, log, target_id, scan_class, phases)
            if h["state"] != "up" and not h["ports"]:
                continue
            hosts_up += 1
            scanned_at = dt.datetime.now().isoformat(timespec="seconds")
            # Доменное имя: если включён dig_rdns (всегда в основном скане,
            # по опции — в расширенном), выполняем обратное разрешение
            # `dig -x <IP>`. PTR-имя приоритетнее hostname из nmap; если dig
            # ничего не вернул — остаётся имя, найденное nmap.
            hostname = h["hostname"]
            if dig_rdns:
                rdns = dig_reverse(h["ip"])
                if rdns:
                    hostname = rdns
            # Обогащение «Доменного имени» именем из DNS-разведки:
            # если nmap и PTR не дали имени, но IP пришёл из домена/
            # поддомена, берём forward-имя, собранное разведкой.
            if not hostname and fqdn_by_ip.get(h["ip"]):
                hostname = fqdn_by_ip[h["ip"]]
            # IP из диапазона CIDR (не из домена) помечаем как 'cidr'.
            if h["ip"] not in ip_sources:
                db.set_ip_origin(target_id, h["ip"], "cidr")
            # alive_no_ports: узел "живой", но ни одного открытого порта не найдено.
            is_anp = (h["state"] == "up") and (len(h["ports"]) == 0)
            host_id = db.add_host(run_id, h["ip"], hostname, h["state"],
                                  scanned_at, alive_no_ports=1 if is_anp else 0)
            if is_anp:
                anp_hosts.append((host_id, h["ip"]))
            # Треб. 2: внешние IP (из DNS-обогащения) — ВНЕ периметра Palo Alto.
            # Для них SYN-flood/SYN-cookie защита не учитывается: открытый порт
            # считается подтверждённым, метка 'syncookie_suspect' снимается.
            is_external = h["ip"] in external_ips
            ports_info = []  # список словарей портов для CVE-анализа
            for p in h["ports"]:
                conf = p["confidence"]
                if is_external and p["state"] == "open" and conf == "syncookie_suspect":
                    conf = "confirmed"
                db.add_port(host_id, p["port"], p["proto"], p["state"],
                            p["service"], p["product"], p["version"],
                            p["extrainfo"], conf)
                ports_info.append({
                    "port": p["port"], "proto": p["proto"],
                    "service": p["service"], "product": p["product"],
                    "version": p["version"], "extrainfo": p["extrainfo"],
                })

            # Web-ресурсы — для портов с http/https/web-сервисами
            if do_web:
                web_ports = [p for p in h["ports"]
                             if p["service"] in ("http", "https", "http-proxy",
                                                 "http-alt", "ssl/http")
                             or p["port"] in (80, 443, 8080, 8443, 8000, 8888)]
                for wp in web_ports:
                    scheme = "https" if (wp["port"] in (443, 8443) or
                                         "https" in wp["service"] or
                                         "ssl" in wp["service"]) else "http"
                    info = webscan.probe_web(h["ip"], wp["port"], scheme,
                                             detail=detail_web)
                    if info:
                        db.add_webres(host_id, info["url"], info["status_code"],
                                      info["title"], info["server"], info["tech"])
                        # Требование 5: базовая проверка на уязвимости.
                        # Тяжёлые/активные инструменты (nikto/wpscan/dalfox)
                        # запускаем только в расширенном скане (advanced),
                        # чтобы не триггерить пороги Palo Alto в основном.
                        heavy = (scan_class == "advanced")
                        try:
                            vfindings = webscan.assess_vulns(
                                info["url"], server=info.get("server", ""),
                                tech=info.get("tech", ""), heavy=heavy,
                                log=log, external=is_external,
                                cve_online=cve_online, cve_vulners=cve_vulners,
                                ports_info=ports_info, detail=detail_web)
                        except Exception as e:  # noqa: BLE001
                            vfindings = []
                            # Через log() — чтобы ошибка попала и в журнал, и в
                            # scan_errors (треб. 3, перехват по шаблону webscan).
                            emsg = f"assess_vulns({info['url']}) ошибка: {e}"
                            log(emsg)
                            log_lines.append(emsg)
                        for vf in vfindings:
                            # Фильтр уровня «инфо» (треб. 6 v1.5.0): если
                            # include_info=False, информационные находки
                            # НЕ фиксируем (в БД попадают только реальные
                            # уязвимости: warning/critical и выше).
                            _sev = str(vf.get("severity", "info")).strip().lower()
                            if not include_info and _sev in _INFO_SEVERITIES:
                                continue
                            db.add_vuln(
                                host_id, vf.get("severity", "info"),
                                vf.get("category"), vf.get("title", ""),
                                detail=vf.get("detail", ""),
                                recommendation=vf.get("recommendation", ""),
                                tool=vf.get("tool", ""),
                                url=vf.get("url", info["url"]),
                                severity_reason=vf.get("severity_reason", ""),
                                cve_id=vf.get("cve_id", ""),
                                cvss=vf.get("cvss", ""),
                                cve_source=vf.get("cve_source", ""))
        # --- alive_no_ports advanced check -------------------------------
        # Если включена галочка/флаг, по каждому "живому без портов" узлу
        # выполняем углублённую перепроверку (3 команды nmap) и сохраняем
        # текстовое пояснение в hosts.advanced_note.
        if advanced_anp and anp_hosts:
            log(f"[*] alive_no_ports advanced check: {len(anp_hosts)} узл(ов) ...")
            log_lines.append(
                f"alive_no_ports advanced check включён: проверяется "
                f"{len(anp_hosts)} узл(ов).")
            # В основном скане (main) — ограниченный режим (bounded), чтобы не висеть.
            bounded = (scan_class == "main")
            for host_id, ip in anp_hosts:
                log(f"    [+] углублённая проверка {ip} ...")
                try:
                    note = advanced_check_alive_no_ports(ip, bounded=bounded)
                except Exception as e:  # noqa: BLE001
                    note = f"ошибка advanced-проверки: {e}"
                db.set_host_advanced(host_id, note)
    else:
        log_lines.append("XML-вывод nmap пуст — узлы не обнаружены или скан прерван.")

    # v1.6.6 (П.1): итоговый пофазовый статус (dns/nmap/webscan) для колонки
    # «Ошибки сканирования» страницы «История сканирований».
    phases["nmap"] = "ok" if nmap_parse_ok else "failed"
    if nmap_crash_retried and nmap_parse_ok:
        phases["nmap_note"] = ("успешно после повтора без NSE-скриптов "
                                "(см. сбой NSE/nsock)")
    phases["webscan"] = ("off" if not do_web
                          else ("ok" if nmap_parse_ok else "skipped"))

    finished = dt.datetime.now().isoformat(timespec="seconds")
    db.finish_run(run_id, "done" if nmap_parse_ok else "error", finished,
                  hosts_up, "\n".join(log_lines))
    try:
        db.set_run_phases_json(run_id, json.dumps(phases, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass

    try:
        os.remove(xml_out)
    except OSError:
        pass

    # П.3: фаза завершения — прогресс-бар показывает все сегменты пройденными.
    _phase(scancontrol.PHASE_DONE)
    # Пересчёт состояния узлов и отличий (только в рамках этого класса)
    diff_engine.update_host_states(target_id, run_id, scan_class=scan_class)

    # Треб. 7: итоговое сообщение о завершении сканирования объекта.
    try:
        vc = db.vuln_severity_counts(run_id)
    except Exception:  # noqa: BLE001
        vc = {"crit": 0, "warn": 0, "info": 0}
    slog.section(
        f"✓ Сканирование объекта «{target['name']}» (запуск #{run_id}, {scan_class}) завершено: "
        f"узлов up {hosts_up}; уязвимостей — крит. {vc.get('crit', 0)}, "
        f"предупр. {vc.get('warn', 0)}, инфо {vc.get('info', 0)}")
    cve_lookup.online_teardown(log=log)   # v1.6.3: завершаем фазу CVE
    slog.close()
    return run_id


def main():
    ap = argparse.ArgumentParser(
        description="Инвентаризационный сканер подсети (Kali 2026.1) с учётом "
                    "Palo Alto SYN Flood / SYN Cookies.")
    # П.2 (v1.6.5): просмотр актуальной установленной версии. Поддерживает
    # как --version, так и -version (одинарное тире, по просьбе).
    ap.add_argument("-version", "--version", action="version",
                    version=appversion.version_string(),
                    help="Показать версию NetInv и выйти")
    ap.add_argument("--target-id", type=int, help="ID объекта из БД")
    ap.add_argument("--add-target", nargs=2, metavar=("NAME", "CIDR"),
                    help="Добавить объект и выйти")
    ap.add_argument("--list-targets", action="store_true")
    ap.add_argument("--profile", default="stealth",
                    choices=list(TIMING_PROFILES.keys()),
                    help="Профиль таймингов под защиту SYN Flood (default: stealth)")
    ap.add_argument("--syn-mode", default="evasion", choices=list(SYN_MODES),
                    help="evasion = обход SYN Flood/SYN Cookies (-sT, по умолч.); "
                         "direct = без обхода (-sS, нужен root)")
    ap.add_argument("--ports", help="Явный список портов, напр. 22,80,443 или 1-1024")
    ap.add_argument("--top-ports", default=DEFAULT_TOP_PORTS)
    ap.add_argument("--full-ports", action="store_true", help="Сканировать все 65535")
    ap.add_argument("--extra-nse", action="store_true",
                    help="Расширенный набор безопасных NSE-скриптов")
    ap.add_argument("--no-web", action="store_true", help="Не сканировать web-ресурсы")
    ap.add_argument("--advanced-anp", action="store_true",
                    help="alive_no_ports advanced check: доп. перепроверка узлов, "
                         "которые живые, но без открытых портов (-p- / --reason / -sU)")
    ap.add_argument("--dig-rdns", action="store_true",
                    help="Обратное разрешение каждого IP через dig -x и запись "
                         "результата в поле «Доменное имя» (в основном скане всегда)")
    ap.add_argument("--dns-brute", action="store_true",
                    help="Brute-force перебор поддоменов словарём "
                         "(dnsmap/dnsenum/dnsrecon); медленнее, но полнее. "
                         "По умолчанию — быстрый/пассивный режим")
    # Треб. 3б: в РАСШИРЕННОМ скане CVE-проверки — опции (вкл/выкл).
    # В ОСНОВНОМ скане они всегда включены (MAIN_PRESET).
    ap.add_argument("--cve-online", dest="cve_online", action="store_true",
                    default=True,
                    help="Онлайн-запрос CVE к NVD/OSV API по версиям ПО "
                         "(расширенный скан; вкл. по умолчанию)")
    ap.add_argument("--no-cve-online", dest="cve_online", action="store_false",
                    help="Отключить онлайн-запрос CVE к NVD/OSV (расширенный скан)")
    ap.add_argument("--vulners", dest="cve_vulners", action="store_true",
                    default=True,
                    help="nmap NSE vulners по версиям ПО "
                         "(расширенный скан; вкл. по умолчанию)")
    ap.add_argument("--no-vulners", dest="cve_vulners", action="store_false",
                    help="Отключить nmap NSE vulners (расширенный скан)")
    # Треб. 6 v1.5.0: фиксация находок уровня «инфо» (по умолч. выкл.).
    ap.add_argument("--include-info", dest="include_info", action="store_true",
                    default=False,
                    help="Фиксировать находки уровня «инфо» (расширенный скан; "
                         "по умолчанию инфо-находки НЕ сохраняются, как и в основном)")
    ap.add_argument("--main", action="store_true",
                    help="ОСНОВНОЙ скан — фиксированный пресет (обход SYN-защиты, "
                         "balanced, NSE, web, alive_no_ports); прочие параметры игнорируются")
    ap.add_argument("--scan-class", choices=("main", "advanced"), default=None,
                    help="Класс сканирования для раздельной статистики (по умолч. "
                         "advanced; --main эквивалентен --scan-class main с пресетом)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Показать команду nmap без запуска")
    args = ap.parse_args()

    db.init_db()

    if args.add_target:
        tid = db.add_target(args.add_target[0], args.add_target[1])
        print(f"[+] Добавлен объект id={tid}: {args.add_target[0]} ({args.add_target[1]})")
        return

    if args.list_targets:
        for t in db.list_targets():
            print(f"{t['id']:>3}  {t['name']:<24} {t['cidr']}")
        return

    if not args.target_id:
        ap.error("Укажите --target-id (см. --list-targets) или --add-target")

    # Основной скан: фиксированный пресет, прочие параметры CLI игнорируются.
    if args.main or args.scan_class == "main":
        run_main_scan(args.target_id, dry_run=args.dry_run)
        return

    run_scan(args.target_id, profile=args.profile, ports=args.ports,
             top_ports=args.top_ports, full_ports=args.full_ports,
             extra_nse=args.extra_nse, do_web=not args.no_web, dry_run=args.dry_run,
             syn_mode=args.syn_mode, advanced_anp=args.advanced_anp,
             dig_rdns=args.dig_rdns, dns_brute=args.dns_brute, scan_class="advanced",
             cve_online=args.cve_online, cve_vulners=args.cve_vulners,
             include_info=args.include_info)


if __name__ == "__main__":
    main()
