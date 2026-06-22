#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webscan.py — выявление и фингерпринт web-ресурсов на открытых портах.

Стратегия (используем предустановленные в Kali инструменты):
  1. Пытаемся получить базовую информацию через curl (код ответа, Server,
     <title>) — он есть всегда и быстр.
  2. Если установлен whatweb — обогащаем технологическим фингерпринтом.

Всё неинтрузивно: только GET корня, без перебора путей и эксплойтов.
Таймауты короткие, чтобы не вешать общий скан и не триггерить пороги firewall.
"""

import re
import shutil
import subprocess

import vuln_rules

CURL = shutil.which("curl")
WHATWEB = shutil.which("whatweb")
NIKTO = shutil.which("nikto")
NMAP = shutil.which("nmap")
WPSCAN = shutil.which("wpscan")
DALFOX = shutil.which("dalfox")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _curl_probe(url):
    """GET корня через curl: код ответа, заголовок Server, <title>."""
    if not CURL:
        return None
    try:
        # -k: игнорируем самоподписанные серты; -s тихо; -L по редиректам;
        # --max-time ограничивает время; -D - выводит заголовки в stdout.
        proc = subprocess.run(
            [CURL, "-sk", "-L", "--max-time", "12", "-A",
             "Mozilla/5.0 (compatible; NetInvScanner/1.0)", "-D", "-", url],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:  # noqa: BLE001
        return None

    out = proc.stdout or ""
    status_code = 0
    server = ""
    # Разбираем последний блок статуса (после редиректов)
    for line in out.splitlines():
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", line)
        if m:
            status_code = int(m.group(1))
        sm = re.match(r"(?i)^server:\s*(.+)$", line.strip())
        if sm:
            server = sm.group(1).strip()

    title = ""
    tm = _TITLE_RE.search(out)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:200]

    if status_code == 0 and not server and not title:
        return None
    return {"status_code": status_code, "server": server, "title": title}


def _whatweb_probe(url):
    """Фингерпринт технологий через whatweb (если доступен)."""
    if not WHATWEB:
        return ""
    try:
        proc = subprocess.run(
            [WHATWEB, "--no-errors", "--color=never", "-a", "1",
             "--max-threads", "1", url],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:  # noqa: BLE001
        return ""
    out = (proc.stdout or "").strip()
    # whatweb выводит "URL [200 OK] Apache[2.4.x], Country[...], ..."
    # Берём содержимое после кода ответа.
    m = re.search(r"\]\s*(.*)$", out)
    tech = m.group(1).strip() if m else out
    return tech[:500]


def probe_web(ip, port, scheme="http"):
    """Вернуть словарь с информацией о web-ресурсе либо None."""
    host = f"{ip}:{port}"
    # Стандартные порты не указываем в URL
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        host = ip
    url = f"{scheme}://{host}/"

    base = _curl_probe(url)
    if base is None:
        # Пробуем альтернативную схему один раз
        alt = "https" if scheme == "http" else "http"
        url2 = f"{alt}://{ip}:{port}/"
        base = _curl_probe(url2)
        if base is None:
            return None
        url = url2

    tech = _whatweb_probe(url)
    return {
        "url": url,
        "status_code": base["status_code"],
        "title": base["title"],
        "server": base["server"],
        "tech": tech,
    }


# ======================================================================
# Требование 5: базовая (неинтрузивная по умолчанию) проверка на уязвимости
# ======================================================================
#
# Принцип: каждый инструмент — ОПЦИОНАЛЬНЫЙ (graceful degradation). Если он не
# установлен (shutil.which == None) — шаг пропускается с предупреждением, скан
# НЕ прерывается. Тяжёлые/активные инструменты (nikto, wpscan, dalfox)
# запускаются только при heavy=True (расширенный скан или по доступности),
# чтобы не триггерить пороги Palo Alto при обычном основном скане.


def _curl_headers(url, timeout=12):
    """Вернуть (status_code, {header_lower: value}) последнего ответа или (0, {})."""
    if not CURL:
        return 0, {}
    try:
        proc = subprocess.run(
            [CURL, "-sk", "-L", "--max-time", str(timeout), "-A",
             "Mozilla/5.0 (compatible; NetInvScanner/1.0)", "-D", "-",
             "-o", "/dev/null", url],
            capture_output=True, text=True, timeout=timeout + 8,
        )
    except Exception:  # noqa: BLE001
        return 0, {}
    headers = {}
    status = 0
    for line in (proc.stdout or "").splitlines():
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", line)
        if m:
            status = int(m.group(1))
            headers = {}  # сбрасываем при каждом новом блоке (после редиректов)
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers


def _curl_path_status(base_url, path, timeout=10):
    """HTTP-код доступности относительного пути (HEAD-подобный GET)."""
    if not CURL:
        return 0
    url = base_url.rstrip("/") + path
    try:
        proc = subprocess.run(
            [CURL, "-sk", "--max-time", str(timeout), "-o", "/dev/null",
             "-w", "%{http_code}", "-A",
             "Mozilla/5.0 (compatible; NetInvScanner/1.0)", url],
            capture_output=True, text=True, timeout=timeout + 6,
        )
    except Exception:  # noqa: BLE001
        return 0
    try:
        return int((proc.stdout or "0").strip()[:3])
    except ValueError:
        return 0


def _run_optional(tool_bin, args, timeout):
    """Запустить опциональный инструмент. Вернуть stdout или None (если
    инструмент отсутствует / ошибка / таймаут) — graceful degradation."""
    if not tool_bin:
        return None
    try:
        proc = subprocess.run([tool_bin] + args, capture_output=True,
                              text=True, timeout=timeout)
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:  # noqa: BLE001
        return None


def assess_vulns(url, server="", tech="", heavy=False, log=None):
    """Базовая проверка web-ресурса на уязвимости (требование 5).

    url    — базовый URL ресурса (например, http://10.0.0.5/);
    server — заголовок Server (из probe_web);
    tech   — фингерпринт whatweb (из probe_web);
    heavy  — запускать ли тяжёлые/активные инструменты (nikto/wpscan/dalfox);
    log    — функция логирования (например, print) для предупреждений.

    Возвращает список находок (dict с ключами severity/category/title/detail/
    recommendation/tool/url) — каждая пригодна для db.add_vuln(...).
    Все инструменты опциональны: отсутствие любого — пропуск с предупреждением.
    """
    def _log(msg):
        if log:
            log("[webscan] " + msg)

    findings = []
    is_https = url.lower().startswith("https://")

    # 1) curl: security-headers ----------------------------------------
    if CURL:
        status, headers = _curl_headers(url)
        findings += vuln_rules.classify_security_headers(
            set(headers.keys()), is_https=is_https)
    else:
        _log("curl не установлен — пропуск проверки security-headers.")

    # 2) curl: открытые конфигурационные/backup-файлы и служебные пути --
    if CURL:
        probe_paths = list(vuln_rules.SECRET_FILES) + list(vuln_rules.ADMIN_PATHS) \
            + list(vuln_rules.TEST_PATHS)
        for path in probe_paths:
            code = _curl_path_status(url, path)
            f = vuln_rules.classify_open_path(path, code)
            if f:
                f["url"] = url.rstrip("/") + path
                findings.append(f)
    # 3) whatweb/Server: устаревшие версии и CMS -----------------------
    findings += vuln_rules.classify_server_version(server)
    findings += vuln_rules.classify_cms(tech)

    # 4) nmap http-NSE (неинтрузивные http-скрипты) --------------------
    if NMAP:
        host_port = _host_port_from_url(url)
        if host_port:
            host, port = host_port
            scripts = ("http-enum,http-headers,http-title,http-wordpress-enum,"
                       "http-security-headers")
            out = _run_optional(
                NMAP, ["-Pn", "-p", str(port), "--script", scripts,
                       "--host-timeout", "120s", host], timeout=180)
            if out:
                findings += vuln_rules.classify_tool_output("nmap-http", out)
    else:
        _log("nmap не установлен — пропуск http-NSE проверок.")

    # ---- Тяжёлые/активные инструменты только при heavy=True ----------
    if heavy:
        # 5) nikto — обзорный web-сканер.
        if NIKTO:
            out = _run_optional(NIKTO, ["-host", url, "-maxtime", "120s",
                                        "-nointeractive", "-ask", "no"],
                                timeout=200)
            if out:
                findings += vuln_rules.classify_tool_output("nikto", out)
        else:
            _log("nikto не установлен — пропуск (опционально).")

        # 6) wpscan — только если по фингерпринту определён WordPress.
        if "wordpress" in (tech or "").lower() or "wp-" in (tech or "").lower():
            if WPSCAN:
                out = _run_optional(
                    WPSCAN, ["--url", url, "--no-banner", "--no-update",
                             "--random-user-agent", "--format", "cli-no-color"],
                    timeout=240)
                if out:
                    findings += vuln_rules.classify_tool_output("wpscan", out)
            else:
                _log("wpscan не установлен — пропуск (опционально, WordPress).")

        # 7) dalfox — лёгкая проверка XSS (только при наличии).
        if DALFOX:
            out = _run_optional(
                DALFOX, ["url", url, "--silence", "--no-color", "--timeout",
                         "10", "--worker", "5"], timeout=180)
            if out:
                findings += vuln_rules.classify_tool_output("dalfox", out)
        else:
            _log("dalfox не установлен — пропуск (опционально).")

    return findings


def _host_port_from_url(url):
    """Извлечь (host, port) из URL для nmap."""
    m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", url)
    if not m:
        return None
    scheme, host, port = m.group(1), m.group(2), m.group(3)
    if not port:
        port = "443" if scheme == "https" else "80"
    return host, int(port)


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        print(probe_web(sys.argv[1], int(sys.argv[2]),
                        sys.argv[3] if len(sys.argv) > 3 else "http"))
