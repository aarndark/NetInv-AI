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

CURL = shutil.which("curl")
WHATWEB = shutil.which("whatweb")

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


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        print(probe_web(sys.argv[1], int(sys.argv[2]),
                        sys.argv[3] if len(sys.argv) > 3 else "http"))
