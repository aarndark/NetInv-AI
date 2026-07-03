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

import random
import re
import shutil
import string
import subprocess

import vuln_rules
import toolpath

# Требование 2 v1.5.0: расширяем PATH процесса типовыми каталогами установки
# (go/bin, snap, /usr/local/bin), чтобы dalfox и др. находились даже когда
# NetInv запущен под web/cron-пользователем без них в PATH.
toolpath.augment_path()

# Поиск утилит — через toolpath.which (PATH + типовые каталоги установки).
CURL = toolpath.which("curl")
WHATWEB = toolpath.which("whatweb")
NIKTO = toolpath.which("nikto")
NMAP = toolpath.which("nmap")
WPSCAN = toolpath.which("wpscan")
DALFOX = toolpath.which("dalfox")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _detail_run(detail, cmd, output, err=""):
    """Записать сырой вывод внешней команды в детальный файл-лог (v1.6.4).

    detail — callback (обычно slog.make_detail_sink('webscan')) или None.
    Пишем саму команду и её stdout/stderr — ТОЛЬКО в файл, не в консоль.
    """
    if not detail:
        return
    try:
        detail("$ " + " ".join(str(c) for c in cmd))
        if output:
            detail("--- stdout ---")
            detail(str(output).rstrip())
        if err:
            detail("--- stderr ---")
            detail(str(err).rstrip())
        detail("--- конец вывода ---")
    except Exception:  # noqa: BLE001
        pass


def _curl_probe(url, detail=None):
    """GET корня через curl: код ответа, заголовок Server, <title>."""
    if not CURL:
        return None
    cmd = [CURL, "-sk", "-L", "--max-time", "12", "-A",
           "Mozilla/5.0 (compatible; NetInvScanner/1.0)", "-D", "-", url]
    try:
        # -k: игнорируем самоподписанные серты; -s тихо; -L по редиректам;
        # --max-time ограничивает время; -D - выводит заголовки в stdout.
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20,
        )
    except Exception as e:  # noqa: BLE001
        _detail_run(detail, cmd, "", f"исключение: {e}")
        return None

    out = proc.stdout or ""
    _detail_run(detail, cmd, out, proc.stderr or "")
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


def _whatweb_probe(url, detail=None):
    """Фингерпринт технологий через whatweb (если доступен)."""
    if not WHATWEB:
        return ""
    cmd = [WHATWEB, "--no-errors", "--color=never", "-a", "1",
           "--max-threads", "1", url]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        _detail_run(detail, cmd, "", f"исключение: {e}")
        return ""
    _detail_run(detail, cmd, proc.stdout or "", proc.stderr or "")
    out = (proc.stdout or "").strip()
    # whatweb выводит "URL [200 OK] Apache[2.4.x], Country[...], ..."
    # Берём содержимое после кода ответа.
    m = re.search(r"\]\s*(.*)$", out)
    tech = m.group(1).strip() if m else out
    return tech[:500]


def probe_web(ip, port, scheme="http", detail=None):
    """Вернуть словарь с информацией о web-ресурсе либо None."""
    host = f"{ip}:{port}"
    # Стандартные порты не указываем в URL
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        host = ip
    url = f"{scheme}://{host}/"

    base = _curl_probe(url, detail=detail)
    if base is None:
        # Пробуем альтернативную схему один раз
        alt = "https" if scheme == "http" else "http"
        url2 = f"{alt}://{ip}:{port}/"
        base = _curl_probe(url2, detail=detail)
        if base is None:
            return None
        url = url2

    tech = _whatweb_probe(url, detail=detail)
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


def _curl_headers(url, timeout=12, detail=None):
    """Вернуть (status_code, {header_lower: value}) последнего ответа или (0, {})."""
    if not CURL:
        return 0, {}
    cmd = [CURL, "-sk", "-L", "--max-time", str(timeout), "-A",
           "Mozilla/5.0 (compatible; NetInvScanner/1.0)", "-D", "-",
           "-o", "/dev/null", url]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 8,
        )
    except Exception as e:  # noqa: BLE001
        _detail_run(detail, cmd, "", f"исключение: {e}")
        return 0, {}
    _detail_run(detail, cmd, proc.stdout or "", proc.stderr or "")
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


def _curl_path(base_url, path, timeout=10, want_body=True, body_limit=8192,
               detail=None):
    """Запросить относительный путь. Вернуть (status_code, body).

    Для контентной валидации (треб. 3) тело ответа ограничено
    body_limit байтами (неинтрузивно, не скачиваем большие файлы).
    """
    if not CURL:
        return 0, ""
    url = base_url.rstrip("/") + path
    # -r 0-8191: берём только начало тела (Range) — экономия и тишина.
    cmd = [CURL, "-sk", "--max-time", str(timeout), "-w",
           "\nNETINV_CODE:%{http_code}", "-A",
           "Mozilla/5.0 (compatible; NetInvScanner/1.4)"]
    if want_body:
        cmd += ["-r", f"0-{body_limit - 1}"]
    else:
        cmd += ["-o", "/dev/null"]
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 6)
    except Exception as e:  # noqa: BLE001
        _detail_run(detail, cmd, "", f"исключение: {e}")
        return 0, ""
    out = proc.stdout or ""
    code = 0
    m = re.search(r"NETINV_CODE:(\d{3})", out)
    if m:
        code = int(m.group(1))
        out = out[:m.start()]
    # Детальный лог: команда + код; тело пишем только при интересном
    # ответе (не 404/000), чтобы не раздувать файл пустыми телами.
    if detail:
        body_for_log = out[:body_limit] if code not in (0, 404) else ""
        _detail_run(detail, cmd, f"HTTP {code}" + (
            "\n" + body_for_log if body_for_log else ""), proc.stderr or "")
    return code, out[:body_limit]


def _curl_path_status(base_url, path, timeout=10, detail=None):
    """Совместимость: только HTTP-код относительного пути."""
    code, _ = _curl_path(base_url, path, timeout=timeout, want_body=False,
                         detail=detail)
    return code


def probe_catch_all(base_url, timeout=8, detail=None):
    """Catch-all detection (треб. 3): отвечает ли сервер 200 на любой путь.

    Пробуем 3 заведомо несуществующих случайных пути. Если сервер на все
    из них отвечает 200 — это catch-all (SPA/прокси/кастомная 200-заглушка),
    и словарные находки по путям будут подавлены (было 84 ложных
    critical). Возвращает True/False.
    """
    if not CURL:
        return False
    hits = 0
    tries = 3
    for _ in range(tries):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        code, _body = _curl_path(base_url, f"/netinv_{rnd}_nonexistent",
                                 timeout=timeout, want_body=False, detail=detail)
        if code == 200:
            hits += 1
    return hits == tries


def _run_optional(tool_bin, args, timeout, detail=None):
    """Запустить опциональный инструмент. Вернуть stdout или None (если
    инструмент отсутствует / ошибка / таймаут) — graceful degradation."""
    if not tool_bin:
        return None
    cmd = [tool_bin] + args
    try:
        proc = subprocess.run(cmd, capture_output=True,
                              text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        _detail_run(detail, cmd, "", f"исключение: {e}")
        return None
    _detail_run(detail, cmd, proc.stdout or "", proc.stderr or "")
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _dedup(findings):
    """Дедупликация находок (треб. 3: раньше каждая находка дублировалась
    для портов 80 и 443). Ключ дедупа: (category, title, cve_id).
    """
    seen = {}
    out = []
    for f in findings:
        key = (f.get("category"), f.get("title"), f.get("cve_id", ""))
        if key in seen:
            continue
        seen[key] = True
        out.append(f)
    return out


def assess_vulns(url, server="", tech="", heavy=False, log=None,
                 external=False, cve_online=True, cve_vulners=True,
                 ports_info=None, detail=None):
    """Проверка web-ресурса на уязвимости (треб. 5, 3, 3б, 2).

    url        — базовый URL ресурса;
    server     — заголовок Server (из probe_web);
    tech       — фингерпринт whatweb;
    heavy      — запускать ли тяжёлые инструменты (nikto/wpscan/dalfox);
    external   — узел во внешнем периметре (IP из DNS, НЕ за Palo Alto):
                 углублённая web-проверка (больше путей, включаем heavy);
    cve_online — онлайн-запрос NVD/OSV по версиям ПО (треб. 3б);
    cve_vulners— nmap NSE vulners по версиям ПО (треб. 3б);
    ports_info — список портов узла [{port, product, version, service}] для CVE;
    detail     — callback детального файл-лога (v1.6.4, Правка 3):
                 сырой вывод curl/whatweb/nikto/... пишется ТОЛЬКО в файл.

    Возвращает ДЕДУПЛИЦИРОВАННЫЙ список находок для db.add_vuln(...).
    Все инструменты опциональны (graceful degradation).
    """
    import cve_lookup

    def _log(msg):
        if log:
            log("[webscan] " + msg)
        # Дублируем в детальный файл-лог (v1.6.4), чтобы контекст
        # решений сохранялся рядом с сырым выводом инструментов.
        if detail:
            detail(msg)

    if detail:
        detail(f"=== assess_vulns начат для {url} "
               f"(server={server!r}, heavy={heavy}, external={external}, "
               f"cve_online={cve_online}, cve_vulners={cve_vulners}, "
               f"портов для CVE={len(ports_info or [])}) ===")

    findings = []
    is_https = url.lower().startswith("https://")

    # 0) Catch-all detection (треб. 3) — подавить ложные 200-находки.
    catch_all = False
    if CURL:
        catch_all = probe_catch_all(url, detail=detail)
        if catch_all:
            _log(f"{url}: сервер отвечает 200 на любой путь (catch-all) — "
                 "словарные находки по путям подавлены.")

    # 1) curl: security-headers ----------------------------------------
    if CURL:
        status, headers = _curl_headers(url, detail=detail)
        findings += vuln_rules.classify_security_headers(
            set(headers.keys()), is_https=is_https)
    else:
        _log("curl не установлен — пропуск проверки security-headers.")

    # 2) curl: служебные пути С КОНТЕНТНОЙ ВАЛИДАЦИЕЙ (треб. 3) ------
    if CURL:
        probe_paths = list(vuln_rules.SECRET_FILES) + list(vuln_rules.ADMIN_PATHS) \
            + list(vuln_rules.TEST_PATHS) + [vuln_rules.SECURITY_TXT]
        # Внешние узлы (корпоративные порталы) — углублённая проверка:
        # дополнительные пути (треб. 2).
        if external:
            probe_paths += ["/.aws/credentials", "/config.json",
                            "/.env.local", "/.env.production",
                            "/wp-config.php", "/api", "/swagger.json",
                            "/.git/", "/storage/logs/laravel.log"]
        for path in probe_paths:
            code, body = _curl_path(url, path, detail=detail)
            f = vuln_rules.classify_open_path(path, code, body=body,
                                              catch_all=catch_all)
            if f:
                f["url"] = url.rstrip("/") + path
                findings.append(f)

    # 3) whatweb/Server: устаревшие версии и CMS ----------------------
    sv = vuln_rules.classify_server_version(server)
    for f in sv:
        f.setdefault("url", url)
    findings += sv
    cm = vuln_rules.classify_cms(tech)
    for f in cm:
        f.setdefault("url", url)
    findings += cm

    # 3б) CVE по версиям ПО (треб. 3б): offline-таблица + онлайн NVD/OSV.
    # В основном скане cve_online и cve_vulners включены по умолчанию.
    for pinfo in (ports_info or []):
        product = pinfo.get("product", "")
        version = pinfo.get("version", "")
        if not product:
            continue
        if detail:
            detail(f"CVE: запрос по порту {pinfo.get('port')} — "
                   f"продукт «{product}» версия «{version or '—'}»")
        try:
            cves = cve_lookup.collect_cves(product, version,
                                           online=cve_online, log=log,
                                           detail=detail)
        except Exception as e:  # noqa: BLE001
            _log(f"CVE-поиск для {product} {version} ошибка: {e}")
            cves = []
        for cve in cves:
            findings.append(cve_lookup.build_cve_finding(
                product, version, url, cve, port=pinfo.get("port")))

    # 3б) nmap NSE vulners по версиям ПО (треб. 3б) -----------------
    if cve_vulners and NMAP:
        host_port = _host_port_from_url(url)
        if host_port:
            host, port = host_port
            out = _run_optional(
                NMAP, ["-Pn", "-sV", "-p", str(port), "--script", "vulners",
                       "--host-timeout", "180s", host], timeout=240,
                detail=detail)
            if out:
                for cve in cve_lookup.parse_vulners_output(out):
                    findings.append(cve_lookup.build_cve_finding(
                        server or "сервис", "", url, cve, port=port))

    # ---- Тяжёлые/активные инструменты ----------
    # Внешние узлы (треб. 2): web-проверку дорабатываем — включаем heavy.
    if external:
        heavy = True
    if heavy:
        # 5) nikto — обзорный web-сканер.
        if NIKTO:
            out = _run_optional(NIKTO, ["-host", url, "-maxtime", "120s",
                                        "-nointeractive", "-ask", "no"],
                                timeout=200, detail=detail)
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
                    timeout=240, detail=detail)
                if out:
                    findings += vuln_rules.classify_tool_output("wpscan", out)
            else:
                _log("wpscan не установлен — пропуск (опционально, WordPress).")

        # 7) dalfox — лёгкая проверка XSS (только при наличии).
        if DALFOX:
            out = _run_optional(
                DALFOX, ["url", url, "--silence", "--no-color", "--timeout",
                         "10", "--worker", "5"], timeout=180, detail=detail)
            if out:
                findings += vuln_rules.classify_tool_output("dalfox", out)
        else:
            _log("dalfox не установлен — пропуск (опционально).")

    # Проставляем URL там, где не задан, и ДЕДУПЛИЦИРУЕМ (треб. 3).
    for f in findings:
        f.setdefault("url", url)
    result = _dedup(findings)
    if detail:
        detail(f"=== assess_vulns завершён для {url}: находок {len(result)} "
               f"(до дедупа {len(findings)}) ===")
    return result


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
