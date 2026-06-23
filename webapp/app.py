#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — Flask + Jinja2 web-приложение для управления инвентаризационным
сканированием подсети (Continuous Penetration Test).

Возможности:
  - Авторизация по локальным пользователям NetInv (доступ только членам
    группы 'cpt'). Пользователи заводятся install.sh при установке.
  - Ввод объектов сканирования (подсети/хосты) через web-форму.
  - Два класса сканирования:
      * ОСНОВНОЙ ('main') — фиксированный пресет (обход SYN-защиты -sT,
        balanced, NSE, web, alive_no_ports). Одна кнопка, без параметров.
      * РАСШИРЕННЫЙ ('advanced') — все параметры выбираемы вручную.
    Статистика и «Отличия от предыдущего» ведутся ОТДЕЛЬНО по каждому классу.
  - Просмотр истории запусков (с классом и краткими опциями).
  - Итоговая таблица по узлам: дата сканирования, IP, доменное имя,
    редактируемое «Описание» (в привязке к IP), открытые порты (с пометкой
    confidence по SYN Cookies) с подсветкой новых/пропавших, сервисы,
    web-ресурсы, дата первого обнаружения, отличия от предыдущего и
    позапрошлого сканирований. Результаты делятся на две части:
    гарантированно «живые» хосты и возможные артефакты защиты Palo Alto.
  - Экспорт таблицы в CSV (файл вида scan_YYYY_MM_DD_TIME.csv).

Запуск:  python3 app.py   (по умолчанию http://127.0.0.1:5000)
"""

import csv
import datetime as dt
import functools
import io
import os
import re
import sys
import threading

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, Response, abort, session, jsonify)
from werkzeug.security import check_password_hash

# Подключаем модули сканера
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scanner"))
import db            # noqa: E402
import diff_engine   # noqa: E402
import scanner       # noqa: E402
import cve_lookup    # noqa: E402

app = Flask(__name__)
app.secret_key = os.environ.get("NETINV_SECRET", "change-me-in-prod")

# Реестр текущих фоновых сканов: run_id -> thread
_RUNNING = {}
_RUNNING_LOCK = threading.Lock()


# ----------------------- авторизация -----------------------

def login_required(view):
    """Декоратор: доступ только авторизованным пользователям группы cpt."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        if not session.get("in_cpt"):
            # Авторизован, но не входит в группу cpt — доступ запрещён.
            session.clear()
            flash("Доступ разрешён только пользователям группы cpt.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    # Если пользователей ещё нет — предупреждаем (их заводит install.sh).
    no_users = (db.count_users() == 0)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = db.get_user(username)
        if not user or not check_password_hash(user["pw_hash"], password):
            flash("Неверное имя пользователя или пароль.", "error")
            return render_template("login.html", no_users=no_users)
        if not user.get("in_cpt"):
            flash("Доступ разрешён только пользователям группы cpt.", "error")
            return render_template("login.html", no_users=no_users)
        session.clear()
        session["user"] = user["username"]
        session["in_cpt"] = bool(user["in_cpt"])
        flash(f"Вы вошли как «{user['username']}».", "ok")
        nxt = request.args.get("next") or request.form.get("next")
        return redirect(nxt or url_for("index"))
    return render_template("login.html", no_users=no_users)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Вы вышли из системы.", "ok")
    return redirect(url_for("login"))


# ----------------------- фоновые сканы -----------------------

def _bg_scan(target_id, profile, ports, top_ports, full_ports, extra_nse, do_web,
             syn_mode, advanced_anp, dig_rdns=False, dns_brute=False,
             cve_online=True, cve_vulners=True):
    """Фоновый РАСШИРЕННЫЙ скан (scan_class='advanced')."""
    try:
        scanner.run_scan(target_id, profile=profile, ports=ports or None,
                         top_ports=top_ports, full_ports=full_ports,
                         extra_nse=extra_nse, do_web=do_web, syn_mode=syn_mode,
                         advanced_anp=advanced_anp, dig_rdns=dig_rdns,
                         dns_brute=dns_brute, scan_class="advanced",
                         cve_online=cve_online, cve_vulners=cve_vulners)
    except Exception as e:  # noqa: BLE001
        app.logger.error("advanced scan failed: %s", e)


def _bg_main_scan(target_id):
    """Фоновый ОСНОВНОЙ скан (фиксированный пресет, scan_class='main')."""
    try:
        scanner.run_main_scan(target_id)
    except Exception as e:  # noqa: BLE001
        app.logger.error("main scan failed: %s", e)


# ----------------------- маршруты -----------------------

@app.route("/")
@login_required
def index():
    targets = db.list_targets()
    # Привязанные домены по каждому объекту (для управления в UI).
    domains_by_target = {t["id"]: db.list_target_domains(t["id"]) for t in targets}
    runs = db.list_runs(limit=15)
    return render_template("index.html", targets=targets, runs=runs,
                           domains_by_target=domains_by_target,
                           profiles=list(scanner.TIMING_PROFILES.keys()),
                           syn_modes=list(scanner.SYN_MODES))


@app.route("/targets/add", methods=["POST"])
@login_required
def add_target():
    name = (request.form.get("name") or "").strip()
    cidr = (request.form.get("cidr") or "").strip()
    desc = (request.form.get("description") or "").strip()
    if not name or not cidr:
        flash("Укажите имя и подсеть/хост (CIDR).", "error")
        return redirect(url_for("index"))
    db.add_target(name, cidr, desc)
    flash(f"Объект «{name}» ({cidr}) добавлен.", "ok")
    return redirect(url_for("index"))


@app.route("/targets/<int:target_id>/delete", methods=["POST"])
@login_required
def delete_target(target_id):
    db.delete_target(target_id)
    flash("Объект удалён.", "ok")
    return redirect(url_for("index"))


@app.route("/targets/<int:target_id>/domains/add", methods=["POST"])
@login_required
def add_domain(target_id):
    """Привязать один или несколько доменов к объекту сканирования.

    Диапазон IP (CIDR) остаётся обязательным; домены — дополнительные
    цели. Допускается несколько доменов через пробел/запятую/перенос строки.
    """
    if not db.get_target(target_id):
        abort(404)
    raw = request.form.get("domains") or ""
    # Разделители: пробел, запятая, точка с запятой, перенос строки.
    items = [d for d in re.split(r"[\s,;]+", raw) if d.strip()]
    added = 0
    for d in items:
        if db.add_target_domain(target_id, d):
            added += 1
    if added:
        flash(f"Добавлено доменов: {added}.", "ok")
    else:
        flash("Новых доменов не добавлено (пусто или дубликаты).", "error")
    return redirect(url_for("index"))


@app.route("/domains/<int:domain_id>/delete", methods=["POST"])
@login_required
def delete_domain(domain_id):
    db.delete_target_domain(domain_id)
    flash("Домен отвязан от объекта.", "ok")
    return redirect(url_for("index"))


@app.route("/scan/main/<int:target_id>", methods=["POST"])
@login_required
def start_main_scan(target_id):
    """ОСНОВНОЙ скан — фиксированный пресет (одна кнопка, без параметров)."""
    target = db.get_target(target_id)
    if not target:
        abort(404)
    t = threading.Thread(target=_bg_main_scan, args=(target_id,), daemon=True)
    t.start()
    flash(f"ОСНОВНОЙ скан объекта «{target['name']}» запущен в фоне "
          f"(пресет: обход SYN-защиты, balanced, NSE, web, alive_no_ports). "
          f"Обновите страницу результатов через время.", "ok")
    return redirect(url_for("report", target_id=target_id, scan_class="main"))


@app.route("/scan/advanced/<int:target_id>", methods=["POST"])
@login_required
def start_advanced_scan(target_id):
    """РАСШИРЕННЫЙ скан — все параметры выбираемы вручную."""
    target = db.get_target(target_id)
    if not target:
        abort(404)
    profile = request.form.get("profile", "stealth")
    syn_mode = request.form.get("syn_mode", "evasion")
    if syn_mode not in scanner.SYN_MODES:
        syn_mode = "evasion"
    ports = (request.form.get("ports") or "").strip()
    top_ports = request.form.get("top_ports", scanner.DEFAULT_TOP_PORTS)
    full_ports = request.form.get("full_ports") == "on"
    extra_nse = request.form.get("extra_nse") == "on"
    do_web = request.form.get("do_web", "on") == "on"
    advanced_anp = request.form.get("advanced_anp") == "on"
    dig_rdns = request.form.get("dig_rdns") == "on"
    dns_brute = request.form.get("dns_brute") == "on"
    # Треб. 3б: в расширенном скане CVE-проверки — опциональны (галочки).
    cve_online = request.form.get("cve_online") == "on"
    cve_vulners = request.form.get("cve_vulners") == "on"

    t = threading.Thread(
        target=_bg_scan,
        args=(target_id, profile, ports, top_ports, full_ports, extra_nse, do_web,
              syn_mode, advanced_anp, dig_rdns, dns_brute, cve_online, cve_vulners),
        daemon=True,
    )
    t.start()
    mode_label = "обход SYN-защиты" if syn_mode == "evasion" else "без обхода"
    anp_label = "; alive_no_ports advanced check вкл." if advanced_anp else ""
    dig_label = "; dig -x (реверсный DNS) вкл." if dig_rdns else ""
    brute_label = "; brute-force поддоменов вкл." if dns_brute else ""
    anp_label = anp_label + dig_label + brute_label
    flash(f"РАСШИРЕННЫЙ скан объекта «{target['name']}» запущен в фоне "
          f"(профиль: {profile}, режим: {mode_label}{anp_label}). "
          f"Обновите страницу результатов через время.", "ok")
    return redirect(url_for("report", target_id=target_id, scan_class="advanced"))


@app.route("/report/<int:target_id>")
@login_required
def report(target_id):
    target = db.get_target(target_id)
    if not target:
        abort(404)
    scan_class = request.args.get("scan_class", "main")
    if scan_class not in ("main", "advanced"):
        scan_class = "main"
    rows = _build_report_rows(target_id, scan_class)
    # Требование 10: делим результаты на «живые» и возможные артефакты Palo Alto.
    live_rows = [r for r in rows if r["is_live"]]
    palo_rows = [r for r in rows if not r["is_live"]]
    runs = db.list_runs(target_id=target_id, limit=30, scan_class=scan_class)
    # Привязанные домены и найденные поддомены объекта.
    domains = db.list_target_domains(target_id)
    subdomains = db.list_subdomains(target_id)
    summary = _report_summary(rows, live_rows, palo_rows)
    return render_template("report.html", target=target,
                           live_rows=live_rows, palo_rows=palo_rows,
                           rows=rows, runs=runs, scan_class=scan_class,
                           domains=domains, subdomains=subdomains,
                           summary=summary)


def _report_summary(rows, live_rows, palo_rows):
    """Краткая сводка по отчёту (треб. 1г) — для главной страницы."""
    crit = warn = info = 0
    for r in rows:
        vc = r.get("vuln_counts", {})
        crit += vc.get("critical", 0)
        warn += vc.get("warning", 0)
        info += vc.get("info", 0)
    return {
        "total": len(rows),
        "live": len(live_rows),
        "palo": len(palo_rows),
        "crit": crit,
        "warn": warn,
        "info": info,
    }


@app.route("/report/<int:target_id>/full")
@login_required
def report_full(target_id):
    """Треб. 1г: отчёт в отдельном окне/вкладке на весь экран.

    Таблица растянута по окну, sticky-заголовки, всегда видимые
    полосы прокрутки, прокрутка стрелками клавиатуры.
    """
    target = db.get_target(target_id)
    if not target:
        abort(404)
    scan_class = request.args.get("scan_class", "main")
    if scan_class not in ("main", "advanced"):
        scan_class = "main"
    rows = _build_report_rows(target_id, scan_class)
    live_rows = [r for r in rows if r["is_live"]]
    palo_rows = [r for r in rows if not r["is_live"]]
    summary = _report_summary(rows, live_rows, palo_rows)
    return render_template("report_full.html", target=target,
                           live_rows=live_rows, palo_rows=palo_rows,
                           rows=rows, scan_class=scan_class, summary=summary)


@app.route("/runs")
@login_required
def runs():
    all_runs = db.list_runs(limit=100)
    return render_template("runs.html", runs=all_runs)


@app.route("/report/<int:target_id>.csv")
@login_required
def report_csv(target_id):
    target = db.get_target(target_id)
    if not target:
        abort(404)
    scan_class = request.args.get("scan_class", "main")
    if scan_class not in ("main", "advanced"):
        scan_class = "main"
    rows = _build_report_rows(target_id, scan_class)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    # Треб. 4: столбец «Присутствие» удалён из CSV (пустой для большинства
    # узлов; смена присутствия уже отражена в столбцах «Отличия…»).
    w.writerow([
        "Дата сканирования", "IP-адрес", "Источник", "Доменное имя", "Описание",
        "Администраторы", "Контроль и защита",
        "Класс сканирования",
        "Открытые порты (с учётом SYN Cookies)", "Опубликованные сервисы",
        "Web-ресурсы", "Уязвимости", "Статус узла", "alive_no_ports advanced check",
        "Первое обнаружение",
        "Дата предыдущего сканирования", "Отличия от предыдущего",
        "Дата позапрошлого сканирования", "Отличия от позапрошлого",
    ])
    class_label = "основное" if scan_class == "main" else "расширенное"
    ctrl_names = {"ctrl_cpt": "CPT", "ctrl_soc": "SOC",
                  "ctrl_vulnscan": "сканер уязвимостей", "ctrl_waf": "WAF",
                  "ctrl_ddos": "DDOS"}
    for r in rows:
        status_label = "alive_no_ports" if r.get("alive_no_ports") else "обычный"
        src_cell = r.get("source_label") or ""
        if r.get("source_domain"):
            src_cell = f"{src_cell} ({r['source_domain']})"
        # «Контроль и защита» — список включённых флагов.
        ctrl_cell = ", ".join(
            label for key, label in ctrl_names.items() if r.get(key))
        # «Уязвимости» — сводка по критичности + заголовки находок.
        vc = r.get("vuln_counts", {})
        vuln_summary = []
        if vc.get("critical"):
            vuln_summary.append(f"критичных: {vc['critical']}")
        if vc.get("warning"):
            vuln_summary.append(f"предупреждений: {vc['warning']}")
        if vc.get("info"):
            vuln_summary.append(f"инфо: {vc['info']}")
        vuln_titles = [f"[{v.get('severity')}] {v.get('title')}"
                       for v in r.get("vulns", [])]
        vuln_cell = "; ".join(vuln_summary)
        if vuln_titles:
            vuln_cell += " | " + " | ".join(vuln_titles)
        w.writerow([
            r["last_scanned_at"], r["ip"], src_cell, r["hostname"] or "",
            r.get("note") or "", r.get("admins") or "", ctrl_cell,
            class_label,
            " | ".join(r["ports_disp"]), " | ".join(r["services_disp"]),
            " | ".join(r["web_disp"]), vuln_cell, status_label,
            r.get("advanced_note") or "",
            r["first_seen"] or "",
            r["prev_scanned_at"] or "", r["diff_prev_text"],
            r["prev2_scanned_at"] or "", r["diff_prev2_text"],
        ])
    data = buf.getvalue().encode("utf-8-sig")  # BOM для Excel
    # Требование 3: имя вида scan_YYYY_MM_DD_TIME.csv по времени запуска скана.
    fname = _csv_filename(rows)
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


def _csv_filename(rows):
    """Имя CSV scan_YYYY_MM_DD_HHMMSS.csv по времени запуска сканирования."""
    started = None
    for r in rows:
        if r.get("last_scanned_at"):
            started = r["last_scanned_at"]
            break
    ts = None
    if started:
        try:
            ts = dt.datetime.fromisoformat(started)
        except (ValueError, TypeError):
            ts = None
    if ts is None:
        ts = dt.datetime.now()
    return ts.strftime("scan_%Y_%m_%d_%H%M%S.csv")


# ----------------------- редактируемое «Описание» (AJAX) -----------------------

@app.route("/note/<int:target_id>", methods=["POST"])
@login_required
def set_note(target_id):
    """Сохранить «Описание» в привязке к IP (AJAX). Требование 4."""
    if not db.get_target(target_id):
        abort(404)
    ip = (request.form.get("ip") or "").strip()
    note = request.form.get("note") or ""
    if not ip:
        return jsonify({"ok": False, "error": "не указан IP"}), 400
    db.set_ip_note(target_id, ip, note)
    return jsonify({"ok": True, "ip": ip, "note": note})


# ----------------------- атрибуты IP: Администраторы / Контроль и защита (AJAX) -

@app.route("/attrs/<int:target_id>", methods=["POST"])
@login_required
def set_attrs(target_id):
    """Сохранить «Администраторы» и/или флаги «Контроль и защита» по IP
    (AJAX). Требование 4. Передаются только изменённые поля."""
    if not db.get_target(target_id):
        abort(404)
    ip = (request.form.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "не указан IP"}), 400
    kwargs = {}
    if "admins" in request.form:
        kwargs["admins"] = request.form.get("admins") or ""
    # Флаги контроля и защиты (любые из набора) — значение "1"/"0".
    for f in db.CTRL_FLAGS:
        if f in request.form:
            kwargs[f] = request.form.get(f) in ("1", "on", "true", "True")
    if not kwargs:
        return jsonify({"ok": False, "error": "нет полей для сохранения"}), 400
    db.set_ip_attributes(target_id, ip, **kwargs)
    return jsonify({"ok": True, "ip": ip})


# ----------------------- подгрузка таблицы по запуску (AJAX-фрагмент) ----------

@app.route("/run/<int:run_id>/rows")
@login_required
def run_rows(run_id):
    """Требование 3: по клику на строку «Истории запусков» вернуть HTML-фрагмент
    с таблицей результатов именно этого запуска (узлы/порты/сервисы/web/
    уязвимости)."""
    run = db.get_run(run_id)
    if not run:
        abort(404)
    target = db.get_target(run["target_id"])
    rows = _build_run_rows(run)
    return render_template("_run_rows.html", rows=rows, run=run, target=target)


def _build_run_rows(run):
    """Строки таблицы по КОНКРЕТНОМУ запуску (а не по сводному состоянию).
    Используется для подгрузки результатов из истории (требование 3)."""
    target_id = run["target_id"]
    run_id = run["id"]
    notes = db.get_ip_notes(target_id)
    attrs = db.get_ip_attributes(target_id)
    origins = db.get_ip_origins(target_id)
    rows = []
    for host in db.hosts_for_run(run_id):
        ip = host["ip"]
        ports_disp, services_disp, web_disp = [], [], []
        vulns, vuln_counts = [], {"critical": 0, "warning": 0, "info": 0}
        for v in db.vulns_for_host(host["id"]):
            vulns.append(v)
            vuln_counts[v.get("severity", "info")] = \
                vuln_counts.get(v.get("severity", "info"), 0) + 1
        for p in db.ports_for_host(host["id"]):
            conf = p.get("confidence", "")
            tag = "" if conf == "confirmed" else f" [{conf}]"
            ports_disp.append(f"{p['port']}/{p['proto']}{tag}")
            svc = " ".join(x for x in [p.get("service"), p.get("product"),
                                       p.get("version")] if x).strip()
            if svc:
                services_disp.append(f"{p['port']}: {svc}")
        for wres in db.webres_for_host(host["id"]):
            web_disp.append(
                f"{wres['url']} [{wres.get('status_code')}] "
                f"{wres.get('server') or ''}".strip())
        ip_attr = attrs.get(ip, {})
        origin = origins.get(ip, {})
        src = origin.get("source") or "cidr"
        src_domain = origin.get("domain") or ""
        src_label = {"cidr": "диапазон (CIDR)", "domain": "домен",
                     "subdomain": "поддомен"}.get(src, src)
        if vuln_counts["critical"]:
            vuln_max = "critical"
        elif vuln_counts["warning"]:
            vuln_max = "warning"
        elif vuln_counts["info"]:
            vuln_max = "info"
        else:
            vuln_max = None
        rows.append({
            "ip": ip,
            "hostname": host.get("hostname") or src_domain or "",
            "note": notes.get(ip, ""),
            "last_scanned_at": host.get("scanned_at") or "",
            "admins": ip_attr.get("admins", ""),
            "ctrl_cpt": ip_attr.get("ctrl_cpt", 0),
            "ctrl_soc": ip_attr.get("ctrl_soc", 0),
            "ctrl_vulnscan": ip_attr.get("ctrl_vulnscan", 0),
            "ctrl_waf": ip_attr.get("ctrl_waf", 0),
            "ctrl_ddos": ip_attr.get("ctrl_ddos", 0),
            "ports_disp": ports_disp or ["—"],
            "services_disp": services_disp or ["—"],
            "web_disp": web_disp or ["—"],
            "vulns": vulns,
            "vuln_counts": vuln_counts,
            "vuln_max": vuln_max,
            "alive_no_ports": bool(host.get("alive_no_ports")),
            "advanced_note": host.get("advanced_note") or "",
            "source": src,
            "source_label": src_label,
            "source_domain": src_domain,
        })
    return rows


# ----------------------- сборка строк отчёта -----------------------

def _build_report_rows(target_id, scan_class="main"):
    """Собрать строки итоговой таблицы по последнему запуску каждого IP
    в рамках класса сканирования scan_class."""
    states = db.report_rows(target_id, scan_class)
    notes = db.get_ip_notes(target_id)
    attrs = db.get_ip_attributes(target_id)  # {ip: {admins, ctrl_*}}
    origins = db.get_ip_origins(target_id)   # {ip: {'source':..., 'domain':...}}
    rows = []
    for st in states:
        last_run = st.get("last_run_id")
        ports_disp, services_disp, web_disp = [], [], []
        vulns = []
        vuln_counts = {"critical": 0, "warning": 0, "info": 0}
        hostname = ""
        alive_no_ports = False
        advanced_note = ""
        has_confirmed = False
        if last_run:
            host = db.host_by_ip_in_run(last_run, st["ip"])
            if host:
                hostname = host.get("hostname") or ""
                alive_no_ports = bool(host.get("alive_no_ports"))
                advanced_note = host.get("advanced_note") or ""
                for v in db.vulns_for_host(host["id"]):
                    # Треб. 3б: кликабельная ссылка NVD для CVE-находок.
                    if v.get("cve_id"):
                        v["nvd_url"] = cve_lookup.nvd_link(v["cve_id"])
                    vulns.append(v)
                    sev = v.get("severity", "info")
                    vuln_counts[sev] = vuln_counts.get(sev, 0) + 1
                for p in db.ports_for_host(host["id"]):
                    conf = p.get("confidence", "")
                    if conf == "confirmed":
                        has_confirmed = True
                    tag = "" if conf == "confirmed" else f" [{conf}]"
                    ports_disp.append(f"{p['port']}/{p['proto']}{tag}")
                    svc = " ".join(x for x in [p.get("service"), p.get("product"),
                                               p.get("version")] if x).strip()
                    if svc:
                        services_disp.append(f"{p['port']}: {svc}")
                for wres in db.webres_for_host(host["id"]):
                    web_disp.append(
                        f"{wres['url']} [{wres.get('status_code')}] "
                        f"{wres.get('server') or ''}".strip())

        # Атрибуты IP: «Администраторы» и «Контроль и защита» (требование 4).
        ip_attr = attrs.get(st["ip"], {})
        # Самый высокий уровень критичности находок (для подсветки строки).
        if vuln_counts["critical"]:
            vuln_max = "critical"
        elif vuln_counts["warning"]:
            vuln_max = "warning"
        elif vuln_counts["info"]:
            vuln_max = "info"
        else:
            vuln_max = None

        flags = diff_engine.diff_flags(st.get("diff_prev"))
        presence = st.get("presence", "pres")
        # Источник IP (CIDR / домен / поддомен) и домен-источник.
        origin = origins.get(st["ip"], {})
        src = origin.get("source") or "cidr"
        src_domain = origin.get("domain") or ""
        src_label = {"cidr": "диапазон (CIDR)",
                     "domain": "домен",
                     "subdomain": "поддомен"}.get(src, src)
        # Если имя хоста пусто, а IP пришёл из домена — подставляем домен.
        if not hostname and not (st.get("hostname")) and src_domain:
            hostname = src_domain
        # Требование 10: «живой» = есть хотя бы один confirmed-сервис.
        # Пропавшие (gone) IP — не живые (в текущем запуске их нет).
        is_live = has_confirmed and presence != "gone"

        rows.append({
            "ip": st["ip"],
            "hostname": hostname or (st.get("hostname") or ""),
            "note": notes.get(st["ip"], ""),
            "last_scanned_at": st.get("last_scanned_at") or "",
            "first_seen": st.get("first_seen") or "",
            "prev_scanned_at": st.get("prev_scanned_at"),
            "prev2_scanned_at": st.get("prev2_scanned_at"),
            "diff_prev_text": diff_engine.diff_to_text(st.get("diff_prev")),
            "diff_prev2_text": diff_engine.diff_to_text(st.get("diff_prev2")),
            # Треб. 1а: блоки отличий построчно (список).
            "diff_prev_lines": diff_engine.diff_to_lines(st.get("diff_prev")),
            "diff_prev2_lines": diff_engine.diff_to_lines(st.get("diff_prev2")),
            "ports_disp": ports_disp or ["—"],
            "services_disp": services_disp or ["—"],
            "web_disp": web_disp or ["—"],
            "alive_no_ports": alive_no_ports,
            "advanced_note": advanced_note,
            # Требование 4: атрибуты IP.
            "admins": ip_attr.get("admins", ""),
            "ctrl_cpt": ip_attr.get("ctrl_cpt", 0),
            "ctrl_soc": ip_attr.get("ctrl_soc", 0),
            "ctrl_vulnscan": ip_attr.get("ctrl_vulnscan", 0),
            "ctrl_waf": ip_attr.get("ctrl_waf", 0),
            "ctrl_ddos": ip_attr.get("ctrl_ddos", 0),
            # Требование 5: уязвимости.
            "vulns": vulns,
            "vuln_counts": vuln_counts,
            "vuln_max": vuln_max,
            "presence": presence,
            "is_live": is_live,
            "source": src,
            "source_label": src_label,
            "source_domain": src_domain,
            # Флаги подсветки (требования 5–8)
            "hl_new_ip": flags["presence_new"],
            "hl_gone_ip": flags["presence_gone"],
            "hl_new_ports": flags["has_new_ports"],
            "hl_gone_ports": flags["has_gone_ports"],
        })
    return rows


@app.template_filter("fmtdate")
def fmtdate(value):
    if not value:
        return "—"
    try:
        return dt.datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return value


@app.template_filter("optsbrief")
def optsbrief(options_json):
    """Краткие опции расширенного запуска для истории (требование 12)."""
    if not options_json:
        return ""
    import json as _json
    try:
        o = _json.loads(options_json)
    except (ValueError, TypeError):
        return ""
    parts = []
    if o.get("syn_mode") == "evasion":
        parts.append("обход SYN-защиты")
    elif o.get("syn_mode") == "direct":
        parts.append("без обхода")
    if o.get("profile"):
        parts.append(f"профиль {o['profile']}")
    if o.get("ports"):
        parts.append(f"порты {o['ports']}")
    if o.get("extra_nse"):
        parts.append("NSE")
    if o.get("do_web"):
        parts.append("web")
    if o.get("advanced_anp"):
        parts.append("alive_no_ports")
    if o.get("dig_rdns"):
        parts.append("dig -x")
    if o.get("dns_brute"):
        parts.append("dns-brute")
    return ", ".join(parts)


@app.context_processor
def inject_user():
    return {"current_user": session.get("user")}


if __name__ == "__main__":
    db.init_db()
    host = os.environ.get("NETINV_HOST", "127.0.0.1")
    port = int(os.environ.get("NETINV_PORT", "5000"))
    app.run(host=host, port=port, debug=False, threaded=True)
