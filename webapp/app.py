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
import logging
import logging.handlers
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
import scancontrol   # noqa: E402
import appversion    # noqa: E402


def _setup_http_logging():
    """П.9 + П.10 (v1.6.5): логи веб-интерфейса — только в файл, не в консоль.

    * П.9: убираем шумный request-лог werkzeug из консоли
      (строки вида ``127.0.0.1 - - [..] "GET /history HTTP/1.1" 200 -``).
    * П.10: направляем их (запросы + ошибки веб-интерфейса) в
      отдельный файл ``./logs/http.log`` для дебага.

    Каталог логов согласован с остальными логами: NETINV_LOG_DIR,
    иначе /opt/netinv/logs, иначе <проект>/logs.
    """
    log_dir = os.environ.get("NETINV_LOG_DIR") or "/opt/netinv/logs"
    try:
        os.makedirs(log_dir, exist_ok=True)
        _probe = os.path.join(log_dir, ".wtest")
        with open(_probe, "w") as f:
            f.write("")
        os.remove(_probe)
    except OSError:
        log_dir = os.path.join(ROOT, "logs")
        os.makedirs(log_dir, exist_ok=True)

    http_log_path = os.path.join(log_dir, "http.log")
    handler = logging.handlers.RotatingFileHandler(
        http_log_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))

    wlog = logging.getLogger("werkzeug")
    wlog.handlers.clear()
    wlog.addHandler(handler)
    wlog.setLevel(logging.INFO)
    # П.9: не пропускать записи вверх к root-логгеру (иначе попадут в консоль).
    wlog.propagate = False

    # Ошибки самого Flask-приложения — тоже в http.log (для дебага).
    app_log = logging.getLogger("netinv.web")
    app_log.handlers.clear()
    app_log.addHandler(handler)
    app_log.setLevel(logging.INFO)
    app_log.propagate = False
    return http_log_path, app_log


app = Flask(__name__)
app.secret_key = os.environ.get("NETINV_SECRET", "change-me-in-prod")
HTTP_LOG_PATH, WEB_LOG = _setup_http_logging()
# П.10: ошибки Flask пишутся в тот же http.log.
for _h in WEB_LOG.handlers:
    app.logger.addHandler(_h)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False

# Реестр текущих фоновых сканов: target_id -> dict(статус).
# v1.6.0 (треб. 4): вкладка «Текущее сканирование» показывает активный скан.
_RUNNING = {}
_RUNNING_LOCK = threading.Lock()


def _running_set(target_id, scan_class, label, control=None):
    """Отметить начало фонового скана объекта (треб. 4).

    v1.6.1 (правка 1): сохраняем объект ScanControl для управления
    паузой/отменой активного скана из веб-интерфейса.
    """
    with _RUNNING_LOCK:
        _RUNNING[int(target_id)] = {
            "target_id": int(target_id),
            "scan_class": scan_class,
            "label": label,
            "started_at": dt.datetime.now().isoformat(timespec="seconds"),
            "control": control,
        }


def _running_clear(target_id):
    """Снять отметку о фоновом скане (по завершению/ошибке)."""
    with _RUNNING_LOCK:
        _RUNNING.pop(int(target_id), None)


def _running_get(target_id):
    with _RUNNING_LOCK:
        st = _RUNNING.get(int(target_id))
        return dict(st) if st else None


def _running_all():
    with _RUNNING_LOCK:
        return {tid: dict(v) for tid, v in _RUNNING.items()}


def _running_control(target_id):
    """Вернуть объект ScanControl активного скана (или None)."""
    with _RUNNING_LOCK:
        st = _RUNNING.get(int(target_id))
        return st.get("control") if st else None


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
             cve_online=True, cve_vulners=True, include_info=False):
    """Фоновый РАСШИРЕННЫЙ скан (scan_class='advanced')."""
    control = scancontrol.ScanControl()
    _running_set(target_id, "advanced", "РАСШИРЕННОЕ сканирование", control=control)
    try:
        scanner.run_scan(target_id, profile=profile, ports=ports or None,
                         top_ports=top_ports, full_ports=full_ports,
                         extra_nse=extra_nse, do_web=do_web, syn_mode=syn_mode,
                         advanced_anp=advanced_anp, dig_rdns=dig_rdns,
                         dns_brute=dns_brute, scan_class="advanced",
                         cve_online=cve_online, cve_vulners=cve_vulners,
                         include_info=include_info, control=control)
    except Exception as e:  # noqa: BLE001
        app.logger.error("advanced scan failed: %s", e)
    finally:
        _running_clear(target_id)


def _bg_main_scan(target_id):
    """Фоновый ОСНОВНОЙ скан (фиксированный пресет, scan_class='main')."""
    control = scancontrol.ScanControl()
    _running_set(target_id, "main", "ОСНОВНОЕ сканирование", control=control)
    try:
        scanner.run_main_scan(target_id, control=control)
    except Exception as e:  # noqa: BLE001
        app.logger.error("main scan failed: %s", e)
    finally:
        _running_clear(target_id)


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
          f"(пресет: обход SYN-защиты, balanced, NSE, web, alive_no_ports).", "ok")
    # П.1 (v1.6.5): после старта скана — сразу на «Текущее сканирование».
    return redirect(url_for("current"))


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
    # Треб. 6 v1.5.0: фиксация находок уровня «инфо» — только по галочке
    # (по умолчанию выкл.). В основном скане инфо-находки не фиксируются всегда.
    include_info = request.form.get("include_info") == "on"

    t = threading.Thread(
        target=_bg_scan,
        args=(target_id, profile, ports, top_ports, full_ports, extra_nse, do_web,
              syn_mode, advanced_anp, dig_rdns, dns_brute, cve_online, cve_vulners,
              include_info),
        daemon=True,
    )
    t.start()
    mode_label = "обход SYN-защиты" if syn_mode == "evasion" else "без обхода"
    anp_label = "; alive_no_ports advanced check вкл." if advanced_anp else ""
    dig_label = "; dig -x (реверсный DNS) вкл." if dig_rdns else ""
    brute_label = "; brute-force поддоменов вкл." if dns_brute else ""
    anp_label = anp_label + dig_label + brute_label
    flash(f"РАСШИРЕННЫЙ скан объекта «{target['name']}» запущен в фоне "
          f"(профиль: {profile}, режим: {mode_label}{anp_label}).", "ok")
    # П.1 (v1.6.5): после старта скана — сразу на «Текущее сканирование».
    return redirect(url_for("current"))


@app.route("/report/<int:target_id>")
@login_required
def report(target_id):
    target = db.get_target(target_id)
    if not target:
        abort(404)
    scan_class = request.args.get("scan_class", "main")
    if scan_class not in ("main", "advanced"):
        scan_class = "main"
    # П.11: тумблер «показать скрытые уязвимости».
    show_hidden = request.args.get("show_hidden") == "1"
    rows = _build_report_rows(target_id, scan_class, show_hidden=show_hidden)
    # Требование 10: делим результаты на «живые» и возможные артефакты Palo Alto.
    live_rows = [r for r in rows if r["is_live"]]
    palo_rows = [r for r in rows if not r["is_live"]]
    raw_runs = db.list_runs(target_id=target_id, limit=30, scan_class=scan_class)
    # v1.6.0 (треб. 1,2,3,4): обогащаем запуски модулями/ошибками/
    # статистикой для новой таблицы истории (Удалить/Опции/Ошибки).
    runs = []
    for r in raw_runs:
        full = db.get_run_full(r["id"]) or r
        full["stats"] = _run_stats(r)
        runs.append(full)
    # Привязанные домены и найденные поддомены объекта.
    domains = db.list_target_domains(target_id)
    subdomains = db.list_subdomains(target_id)
    summary = _report_summary(rows, live_rows, palo_rows)
    return render_template("report.html", target=target,
                           live_rows=live_rows, palo_rows=palo_rows,
                           rows=rows, runs=runs, scan_class=scan_class,
                           domains=domains, subdomains=subdomains,
                           summary=summary, show_hidden=show_hidden)


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
    show_hidden = request.args.get("show_hidden") == "1"
    rows = _build_report_rows(target_id, scan_class, show_hidden=show_hidden)
    live_rows = [r for r in rows if r["is_live"]]
    palo_rows = [r for r in rows if not r["is_live"]]
    summary = _report_summary(rows, live_rows, palo_rows)
    return render_template("report_full.html", target=target,
                           live_rows=live_rows, palo_rows=palo_rows,
                           rows=rows, scan_class=scan_class, summary=summary,
                           show_hidden=show_hidden)


@app.route("/runs")
@login_required
def runs():
    all_runs = db.list_runs(limit=100)
    return render_template("runs.html", runs=all_runs)


# ============ v1.6.0 (треб. 4): 3 вкладки ============

def _run_stats(run):
    """Статистика по конкретному запуску (треб. 4): всего узлов,
    живые, артефакты Palo Alto, открытые порты, уникальные поддомены."""
    run_id = run["id"]
    hosts = db.hosts_for_run(run_id)
    total = len(hosts)
    live = palo = open_ports = 0
    for h in hosts:
        confirmed = False
        n_ports = 0
        for p in db.ports_for_host(h["id"]):
            n_ports += 1
            if p.get("confidence") == "confirmed":
                confirmed = True
        open_ports += n_ports
        if confirmed:
            live += 1
        else:
            palo += 1
    # Уникальные поддомены, отмеченные этим запуском.
    subs = [s for s in db.list_subdomains(run["target_id"])
            if s.get("last_run_id") == run_id]
    return {
        "total": total,
        "live": live,
        "palo": palo,
        "open_ports": open_ports,
        "subdomains": len(subs),
    }


def _subdomain_summary(target_id):
    """Сводка по поддоменам объекта: всего, новые,
    исчезнувшие.

    v1.6.1 (правка 3): конфликты IP теперь разрешаются
    автоматически (одна пара домен–IP в таблице один раз),
    поэтому вместо «конфликтов» считаем число автоматически
    разрешённых записей (auto_resolved).
    """
    subs = db.list_subdomains(target_id)
    present = [s for s in subs if s.get("present")]
    gone = [s for s in subs if not s.get("present")]
    auto_resolved = [s for s in subs if s.get("auto_resolved")]
    # v1.6.4 (Правка 1): артефакты обнаружения (не прошли проверку IP).
    artifacts = [s for s in subs if s.get("is_artifact")]
    return {
        "total": len(subs),
        "present": len(present),
        "gone": len(gone),
        "auto_resolved": len(auto_resolved),
        "artifacts": len(artifacts),
    }


@app.route("/current")
@login_required
def current():
    """Вкладка «Текущее сканирование» (треб. 4).

    Если есть активные фоновые сканы — показываем их статус. Иначе —
    результаты ПОСЛЕДНЕГО основного скана (как на /report/) +
    поддомены + ошибки этого запуска.
    """
    # Баг (v1.6.8): на /current не было переключателя «показать скрытые
    # уязвимости» — раньше это было незаметно, т.к. кнопки Скрыть/Копировать
    # тут вовсе не работали (баг 3, v1.6.7), а после их исправления скрытые
    # уязвимости стало некуда вернуть без перехода в «Полный отчёт объекта».
    show_hidden = request.args.get("show_hidden") == "1"
    active = _running_all()
    targets = db.list_targets()
    tmap = {t["id"]: t for t in targets}
    active_list = []
    for tid, st in active.items():
        st = dict(st)
        st["target"] = tmap.get(tid)
        # v1.6.1 (правка 1): состояние скана (running/paused/cancelling)
        # для кнопок управления. Объект control не передаём в шаблон.
        ctrl = st.pop("control", None)
        st["state"] = ctrl.state() if ctrl is not None else scancontrol.STATE_RUNNING
        active_list.append(st)
    active_list.sort(key=lambda s: s.get("started_at") or "")

    # Последний завершённый основной скан (для фолбэка, если нет активных).
    last_main = None
    last_run = None
    all_main = db.list_runs(limit=1, scan_class="main")
    if all_main:
        last_run = db.get_run_full(all_main[0]["id"])
        last_main = tmap.get(all_main[0]["target_id"])

    rows = live_rows = palo_rows = None
    summary = subdomains = subs_summary = errors = None
    scan_class = "main"
    if last_run and not active_list:
        target_id = last_run["target_id"]
        rows = _build_report_rows(target_id, "main", show_hidden=show_hidden)
        live_rows = [r for r in rows if r["is_live"]]
        palo_rows = [r for r in rows if not r["is_live"]]
        summary = _report_summary(rows, live_rows, palo_rows)
        subdomains = db.list_subdomains(target_id)
        subs_summary = _subdomain_summary(target_id)
        errors = last_run.get("errors") or {}
    return render_template("current.html",
                           active_list=active_list,
                           last_run=last_run, last_target=last_main,
                           rows=rows, live_rows=live_rows, palo_rows=palo_rows,
                           summary=summary, subdomains=subdomains,
                           subs_summary=subs_summary, errors=errors,
                           scan_class=scan_class, show_hidden=show_hidden)


@app.route("/current/status")
@login_required
def current_status():
    """AJAX-опрос статуса активных сканов (треб. 4, автообновление)."""
    active = _running_all()
    tmap = {t["id"]: t for t in db.list_targets()}
    out = []
    for tid, st in active.items():
        ctrl = st.get("control")
        # П.3: текущая фаза скана (dns/nmap/webscan/done) для прогресс-бара.
        phase = ctrl.phase() if ctrl is not None else None
        # П.3: есть ли у объекта домены — если нет, сегмент dns скрывается.
        try:
            has_domains = bool(db.domains_for_target(tid))
        except Exception:  # noqa: BLE001
            has_domains = False
        out.append({
            "target_id": tid,
            "target_name": (tmap.get(tid) or {}).get("name", f"#{tid}"),
            "scan_class": st.get("scan_class"),
            "label": st.get("label"),
            "started_at": st.get("started_at"),
            # v1.6.1 (правка 1): текущее состояние для кнопок управления.
            "state": ctrl.state() if ctrl is not None else scancontrol.STATE_RUNNING,
            # П.3: данные прогресс-бара.
            "phase": phase,
            "has_domains": has_domains,
        })
    return jsonify({
        "running": out,
        "count": len(out),
        # П.3: порядок и RU-метки фаз для отрисовки полосы.
        "phase_order": scancontrol.PHASE_ORDER,
        "phase_labels": scancontrol.PHASE_LABELS,
    })


# --- v1.6.1 (правка 1): управление активным сканом ---

@app.route("/current/<int:target_id>/pause", methods=["POST"])
@login_required
def current_pause(target_id):
    """Приостановить активный скан объекта (правка 1)."""
    ctrl = _running_control(target_id)
    if ctrl is None:
        return _control_response(target_id, ok=False, msg="Скан не активен.")
    ctrl.request_pause()
    return _control_response(target_id, ok=True, msg="Сканирование приостановлено.")


@app.route("/current/<int:target_id>/resume", methods=["POST"])
@login_required
def current_resume(target_id):
    """Возобновить приостановленный скан (правка 1)."""
    ctrl = _running_control(target_id)
    if ctrl is None:
        return _control_response(target_id, ok=False, msg="Скан не активен.")
    ctrl.request_resume()
    return _control_response(target_id, ok=True, msg="Сканирование возобновлено.")


@app.route("/current/<int:target_id>/cancel", methods=["POST"])
@login_required
def current_cancel(target_id):
    """Отменить активный скан объекта (правка 1)."""
    ctrl = _running_control(target_id)
    if ctrl is None:
        return _control_response(target_id, ok=False, msg="Скан не активен.")
    ctrl.request_cancel()
    return _control_response(target_id, ok=True, msg="Сканирование отменяется…")


def _control_response(target_id, ok, msg):
    """Ответ на управляющий запрос: JSON для AJAX, иначе redirect."""
    wants_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if wants_json:
        ctrl = _running_control(target_id)
        state = ctrl.state() if ctrl is not None else None
        return jsonify({"ok": ok, "message": msg, "state": state})
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("current"))


@app.route("/history")
@login_required
def history():
    """Вкладка «История сканирований» (треб. 4) с разбивкой по
    объектам, фильтрами, статистикой и выбором для сравнения."""
    f_target = request.args.get("target_id", type=int)
    f_class = request.args.get("scan_class") or ""
    f_from = (request.args.get("date_from") or "").strip()
    f_to = (request.args.get("date_to") or "").strip()
    if f_class not in ("main", "advanced"):
        f_class = ""

    runs = db.list_runs(target_id=f_target or None, limit=500,
                        scan_class=f_class or None)
    # Фильтр по датам (по started_at, префикс YYYY-MM-DD).
    def _in_range(r):
        d = (r.get("started_at") or "")[:10]
        if f_from and d < f_from:
            return False
        if f_to and d > f_to:
            return False
        return True
    runs = [r for r in runs if _in_range(r)]

    # Статистика по каждому запуску + разбивка по объектам.
    groups = {}  # target_id -> {"target":..., "runs":[...]}
    for r in runs:
        full = db.get_run_full(r["id"]) or r
        full["stats"] = _run_stats(r)
        g = groups.setdefault(r["target_id"], {
            "target_id": r["target_id"],
            "target_name": r.get("target_name"),
            "target_cidr": r.get("target_cidr"),
            "runs": [],
        })
        g["runs"].append(full)
    group_list = sorted(groups.values(),
                        key=lambda g: (g["target_name"] or "").lower())

    targets = db.list_targets()
    return render_template("history.html", groups=group_list,
                           targets=targets, f_target=f_target,
                           f_class=f_class, f_from=f_from, f_to=f_to)


# ============ v1.6.0 (треб. 1): удаление запуска ============

@app.route("/run/<int:run_id>/delete", methods=["POST"])
@login_required
def delete_run(run_id):
    """Удалить нерепрезентативный запуск (треб. 1) + пересчёт host_state."""
    run = db.get_run(run_id)
    if not run:
        abort(404)
    res = db.delete_run(run_id)
    if res:
        target_id, scan_class = res
        # Полный пересчёт состояний узлов объекта в рамках класса.
        diff_engine.rebuild_host_states(target_id, scan_class)
        flash("Запуск удалён, история и состояния узлов пересчитаны.", "ok")
    else:
        flash("Запуск не найден (возможно, уже удалён).", "error")
    return redirect(request.referrer or url_for("history"))


# ============ v1.6.0 (треб. 4): сравнение до 5 запусков ============

def _parse_run_ids(raw):
    """Разобрать список run_id из запроса (сохраняя порядок выбора)."""
    ids = []
    for part in re.split(r"[,\s]+", raw or ""):
        part = part.strip()
        if part.isdigit():
            v = int(part)
            if v not in ids:
                ids.append(v)
    return ids


def _build_compare(run_ids, baseline_id=None):
    """Собрать данные сравнения до 5 запусков (треб. 4).

    Эталон = ПЕРВОЕ выбранное по умолчанию. v1.6.5 (доработка 7):
    эталонное сканирование можно выбрать прямо в окне сравнения —
    если задан baseline_id и он присутствует среди выбранных, этот
    запуск ставится первым (нулевой колонкой). Колонки «Отличия от
    сканирования <дата>» идут по порядку выбора. Сравнение по IP +
    списку открытых портов (множества).
    """
    ids = list(run_ids[:5])
    # v1.6.5 (доработка 7): переставить выбранный эталон в начало.
    if baseline_id is not None and baseline_id in ids:
        ids.remove(baseline_id)
        ids.insert(0, baseline_id)
    runs = []
    for rid in ids:
        r = db.get_run_full(rid)
        if r:
            runs.append(r)
    # Снимок каждого запуска: {ip: set(port/proto)}.
    snaps = []
    for r in runs:
        snap = {}
        for h in db.hosts_for_run(r["id"]):
            ports = set()
            for p in db.ports_for_host(h["id"]):
                ports.add(f"{p['port']}/{p['proto']}")
            snap[h["ip"]] = ports
        snaps.append(snap)
    base_snap = snaps[0] if snaps else {}
    # Строки — объединение всех IP.
    all_ips = set()
    for s in snaps:
        all_ips |= set(s.keys())
    rows = []
    for ip in sorted(all_ips, key=db.ip_sort_key):
        cells = []
        for idx, snap in enumerate(snaps):
            ports = snap.get(ip)
            present = ip in snap
            if idx == 0:
                cells.append({
                    "present": present,
                    "ports": sorted(ports or []),
                    "diff": None,
                })
                continue
            # Отличия от эталона (первого).
            base_ports = base_snap.get(ip, set())
            diff = {"presence": None, "new_ports": [], "gone_ports": []}
            if present and ip not in base_snap:
                diff["presence"] = "новый IP"
            elif not present and ip in base_snap:
                diff["presence"] = "IP отсутствует"
            if present:
                diff["new_ports"] = sorted((ports or set()) - base_ports)
                diff["gone_ports"] = sorted(base_ports - (ports or set()))
            cells.append({
                "present": present,
                "ports": sorted(ports or []),
                "diff": diff,
            })
        rows.append({"ip": ip, "cells": cells})
    return runs, rows


@app.route("/compare")
@login_required
def compare():
    """Сравнение до 5 запусков (треб. 4). Параметр ids=1,2,3."""
    ids = _parse_run_ids(request.args.get("ids", ""))
    if len(ids) < 2:
        flash("Выберите от 2 до 5 запусков для сравнения.", "error")
        return redirect(url_for("history"))
    if len(ids) > 5:
        ids = ids[:5]
        flash("Сравнение ограничено 5 запусками — взяты первые 5.", "error")
    # v1.6.5 (доработка 7): выбор эталонного сканирования прямо в окне.
    try:
        baseline_id = int(request.args.get("baseline", ""))
    except (TypeError, ValueError):
        baseline_id = None
    if baseline_id not in ids:
        baseline_id = ids[0]
    runs, rows = _build_compare(ids, baseline_id=baseline_id)
    if len(runs) < 2:
        flash("Не удалось найти достаточно запусков для сравнения.", "error")
        return redirect(url_for("history"))
    return render_template("compare.html", runs=runs, rows=rows,
                           ids_str=",".join(str(i) for i in ids),
                           baseline_id=baseline_id)


# ============ v1.6.0 (треб. 5): окно поддоменов ============

@app.route("/subdomains/<int:target_id>")
@login_required
def subdomains_window(target_id):
    """Окно «Поддомены» (треб. 5): FQDN, IP, первое/последнее
    обнаружение + утилита, подсветка новых/исчезнувших, конфликты IP."""
    target = db.get_target(target_id)
    if not target:
        abort(404)
    subs = db.list_subdomains(target_id)
    # v1.6.1 (правка 3): конфликты разрешаются автоматически после
    # каждого скана. Подготавливаем сводную информацию по утилитам
    # и разрешённым конфликтам для столбца «Информация».
    for s in subs:
        tools = [t.strip() for t in (s.get("tools") or s.get("tool") or "").split(",")
                 if t.strip()]
        s["tools_list"] = tools
        alt = [ip.strip() for ip in (s.get("alt_ips") or "").split(",")
               if ip.strip()]
        s["alt_ips_list"] = alt
    summary = _subdomain_summary(target_id)
    return render_template("subdomains.html", target=target, subs=subs,
                           summary=summary)


@app.route("/subdomains/<int:target_id>/bind", methods=["POST"])
@login_required
def subdomains_bind(target_id):
    """Привязать/отвязать поддомены (треб. 5). Один/все, с подтверждением."""
    if not db.get_target(target_id):
        abort(404)
    action = request.form.get("action", "")
    subdomain = (request.form.get("subdomain") or "").strip()
    if action == "bind_one" and subdomain:
        db.set_subdomain_bound(target_id, subdomain, True)
        # v1.6.5 (доработка 6): родительский домен привязанного
        # поддомена автоматически добавляется в описание объекта
        # и участвует в будущих сканированиях.
        added = db.sync_bound_domains_to_target(target_id)
        msg = f"Поддомен {subdomain} привязан к объекту."
        if added:
            msg += f" Добавлено доменов в объект: {added}."
        flash(msg, "ok")
    elif action == "unbind_one" and subdomain:
        db.set_subdomain_bound(target_id, subdomain, False)
        flash(f"Поддомен {subdomain} отвязан от объекта.", "ok")
    elif action == "bind_all_new":
        n = db.set_all_subdomains_bound(target_id, True, only_present=True)
        # v1.6.5 (доработка 6): все родительские домены привязанных
        # поддоменов синхронизируются в target_domains.
        added = db.sync_bound_domains_to_target(target_id)
        msg = f"Привязано новых поддоменов с IP: {n}."
        if added:
            msg += f" Добавлено доменов в объект: {added}."
        flash(msg, "ok")
    elif action == "unbind_all_gone":
        n = db.set_all_subdomains_bound(target_id, False, only_present=True)
        flash(f"Отвязано исчезнувших поддоменов: {n}.", "ok")
    else:
        flash("Неизвестное действие или не указан поддомен.", "error")
    return redirect(url_for("subdomains_window", target_id=target_id))


@app.route("/subdomains/<int:target_id>/resolve", methods=["POST"])
@login_required
def subdomains_resolve(target_id):
    """Разрешить конфликт разных IP (треб. 5): dnsmap vs dnsrecon."""
    if not db.get_target(target_id):
        abort(404)
    subdomain = (request.form.get("subdomain") or "").strip()
    resolved_ip = (request.form.get("resolved_ip") or "").strip()
    if not subdomain or not resolved_ip:
        flash("Укажите поддомен и разрешённый IP.", "error")
        return redirect(url_for("subdomains_window", target_id=target_id))
    db.resolve_subdomain_ip(target_id, subdomain, resolved_ip)
    flash(f"Конфликт IP для {subdomain} разрешён: {resolved_ip}.", "ok")
    return redirect(url_for("subdomains_window", target_id=target_id))


# ============ v1.6.0 (треб. 4): ссылка на лог ============

@app.route("/log/<int:run_id>")
@login_required
def view_log(run_id):
    """Отдать файл лога запуска (треб. 4, «ссылка на лог»)."""
    run = db.get_run(run_id)
    if not run:
        abort(404)
    path = run.get("log_path")
    if not path or not os.path.exists(path):
        flash("Файл лога недоступен (возможно, удалён или запуск старый).",
              "error")
        return redirect(request.referrer or url_for("history"))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        flash(f"Не удалось прочитать лог: {e}", "error")
        return redirect(request.referrer or url_for("history"))
    return Response(data, mimetype="text/plain; charset=utf-8")


# ----------------------- П.11: разбор уязвимостей -----------------------

@app.route("/triage")
@login_required
def triage():
    """П.11: страница «Разбор уязвимостей» — таблица принятых в работу.

    Показывает уязвимости со состоянием 'accepted' по всем объектам.
    Опции по каждой: открыть лог, отменить рассмотрение, скрыть, комментарий.
    """
    items = db.list_all_vuln_states(state="accepted")
    return render_template("triage.html", items=items, active_tab="triage")


def _vuln_state_fields():
    """П.11: собрать снимок полей уязвимости из POST-формы."""
    f = request.form
    log_run_id = f.get("log_run_id") or None
    try:
        log_run_id = int(log_run_id) if log_run_id else None
    except (ValueError, TypeError):
        log_run_id = None
    return {
        "ip": f.get("ip", ""),
        "port": f.get("port", ""),
        "title": f.get("title", ""),
        "cve_id": f.get("cve_id", ""),
        "cvss": f.get("cvss", ""),
        "severity": f.get("severity", ""),
        "detail": f.get("detail", ""),
        "recommendation": f.get("recommendation", ""),
        "tool": f.get("tool", ""),
        "url": f.get("url", ""),
        "log_run_id": log_run_id,
    }


@app.route("/vuln/<int:target_id>/hide", methods=["POST"])
@login_required
def vuln_hide(target_id):
    """П.11: скрыть уязвимость (принятие риска / ошибка детекции)."""
    vkey = request.form.get("vkey", "").strip()
    if not vkey:
        return _vuln_resp(False, "Не указан ключ уязвимости")
    db.set_vuln_state(target_id, vkey, "hidden", **_vuln_state_fields())
    return _vuln_resp(True, "Уязвимость скрыта")


@app.route("/vuln/<int:target_id>/accept", methods=["POST"])
@login_required
def vuln_accept(target_id):
    """П.11: принять уязвимость в работу (попадает в «Разбор»)."""
    vkey = request.form.get("vkey", "").strip()
    if not vkey:
        return _vuln_resp(False, "Не указан ключ уязвимости")
    db.set_vuln_state(target_id, vkey, "accepted", **_vuln_state_fields())
    return _vuln_resp(True, "Уязвимость принята в работу")


@app.route("/vuln/<int:target_id>/clear", methods=["POST"])
@login_required
def vuln_clear(target_id):
    """П.11: отменить рассмотрение / снять состояние."""
    vkey = request.form.get("vkey", "").strip()
    if not vkey:
        return _vuln_resp(False, "Не указан ключ уязвимости")
    db.clear_vuln_state(target_id, vkey)
    return _vuln_resp(True, "Состояние снято")


@app.route("/vuln/<int:target_id>/comment", methods=["POST"])
@login_required
def vuln_comment(target_id):
    """П.11: сохранить комментарий к принятой уязвимости."""
    vkey = request.form.get("vkey", "").strip()
    if not vkey:
        return _vuln_resp(False, "Не указан ключ уязвимости")
    db.set_vuln_comment(target_id, vkey, request.form.get("comment", ""))
    return _vuln_resp(True, "Комментарий сохранён")


def _vuln_resp(ok, msg):
    """П.11: единый ответ для AJAX (JSON) и обычных форм (redirect с flash)."""
    wants_json = (request.headers.get("X-Requested-With") == "XMLHttpRequest"
                  or "application/json" in (request.headers.get("Accept") or ""))
    if wants_json:
        return jsonify({"ok": ok, "message": msg})
    flash(msg, "info" if ok else "error")
    return redirect(request.referrer or url_for("index"))


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


# v1.6.0 (треб. 4): CSV одного запуска (по run_id) и сравнения.
@app.route("/run/<int:run_id>.csv")
@login_required
def run_csv(run_id):
    """CSV конкретного запуска из истории (треб. 4)."""
    run = db.get_run(run_id)
    if not run:
        abort(404)
    rows = _build_run_rows(run)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([
        "Дата сканирования", "IP-адрес", "Источник", "Доменное имя", "Описание",
        "Открытые порты", "Опубликованные сервисы", "Web-ресурсы",
        "Статус узла",
    ])
    for r in rows:
        status_label = "alive_no_ports" if r.get("alive_no_ports") else "обычный"
        src_cell = r.get("source_label") or ""
        if r.get("source_domain"):
            src_cell = f"{src_cell} ({r['source_domain']})"
        w.writerow([
            r["last_scanned_at"], r["ip"], src_cell, r["hostname"] or "",
            r.get("note") or "",
            " | ".join(r["ports_disp"]), " | ".join(r["services_disp"]),
            " | ".join(r["web_disp"]), status_label,
        ])
    data = buf.getvalue().encode("utf-8-sig")
    ts = run.get("started_at") or ""
    try:
        ts = dt.datetime.fromisoformat(ts).strftime("%Y_%m_%d_%H%M%S")
    except (ValueError, TypeError):
        ts = dt.datetime.now().strftime("%Y_%m_%d_%H%M%S")
    fname = f"scan_run{run_id}_{ts}.csv"
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/compare.csv")
@login_required
def compare_csv():
    """CSV сравнения до 5 запусков (треб. 4). Параметр ids=1,2,3."""
    ids = _parse_run_ids(request.args.get("ids", ""))[:5]
    if len(ids) < 2:
        abort(400)
    runs, rows = _build_compare(ids)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    header = ["IP-адрес"]
    for idx, run in enumerate(runs):
        d = fmtdate(run.get("started_at"))
        if idx == 0:
            header.append(f"Эталон: {d} ({run.get('scan_class')})")
        else:
            header.append(f"Отличия от эталона: {d} ({run.get('scan_class')})")
    w.writerow(header)
    for row in rows:
        cells = [row["ip"]]
        for idx, cell in enumerate(row["cells"]):
            if idx == 0:
                cells.append(", ".join(cell["ports"]) if cell["present"]
                             else "отсутствует")
                continue
            d = cell.get("diff") or {}
            parts = []
            if d.get("presence"):
                parts.append(d["presence"])
            if d.get("new_ports"):
                parts.append("+порты: " + ", ".join(d["new_ports"]))
            if d.get("gone_ports"):
                parts.append("-порты: " + ", ".join(d["gone_ports"]))
            cells.append("; ".join(parts) if parts else "без изменений")
        w.writerow(cells)
    data = buf.getvalue().encode("utf-8-sig")
    fname = "compare_" + "_".join(str(i) for i in ids) + ".csv"
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


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
    # П.11: тумблер «показать скрытые» прокидываем через run.
    run["_show_hidden"] = request.args.get("show_hidden") == "1"
    rows = _build_run_rows(run)
    return render_template("_run_rows.html", rows=rows, run=run, target=target,
                           show_hidden=run["_show_hidden"])


def _build_run_rows(run):
    """Строки таблицы по КОНКРЕТНОМУ запуску (а не по сводному состоянию).
    Используется для подгрузки результатов из истории (требование 3)."""
    target_id = run["target_id"]
    run_id = run["id"]
    show_hidden = bool(run.get("_show_hidden"))  # П.11: прокидывается через run
    notes = db.get_ip_notes(target_id)
    attrs = db.get_ip_attributes(target_id)
    origins = db.get_ip_origins(target_id)
    vstates = db.get_vuln_states(target_id)  # П.11: состояния скрытия/принятия
    rows = []
    for host in db.hosts_for_run(run_id):
        ip = host["ip"]
        ports_disp, services_disp, web_disp = [], [], []
        # П.11: прикрепляем vkey/vstate, скрытые по умолчанию не показываем.
        raw_vulns = []
        for v in db.vulns_for_host(host["id"]):
            v["run_id"] = run_id
            raw_vulns.append(v)
        vulns, vuln_counts, hidden_count = _apply_vuln_states(
            raw_vulns, ip, target_id, vstates, show_hidden=show_hidden)
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
            "vuln_hidden_count": hidden_count,  # П.11
            "alive_no_ports": bool(host.get("alive_no_ports")),
            "advanced_note": host.get("advanced_note") or "",
            "source": src,
            "source_label": src_label,
            "source_domain": src_domain,
        })
    return rows


# ----------------------- сборка строк отчёта -----------------------

def _vuln_port(v):
    """П.11: вытащить порт для ключа уязвимости из url (если есть).

    Ключ = IP + порт + название/CVE. Порт берём из URL вида
    http://host:8080/... — явный порт; иначе 80/443 по схеме; иначе пусто.
    """
    url = (v.get("url") or "").strip()
    if not url:
        return ""
    m = re.search(r"://[^/:]+:(\d+)", url)
    if m:
        return m.group(1)
    if url.startswith("https://"):
        return "443"
    if url.startswith("http://"):
        return "80"
    return ""


def _apply_vuln_states(vulns, ip, target_id, states_map, show_hidden=False):
    """П.11: прикрепить vkey/состояние, отфильтровать скрытые и пересчитать счётчики.

    Возвращает (visible_vulns, counts, hidden_count):
      * каждой уязвимости добавляются vkey, vstate ('hidden'|'accepted'|'');
      * скрытые (state='hidden') исключаются из списка и счётчиков,
        если show_hidden=False (П.11: по умолчанию скрыты);
      * при show_hidden=True скрытые показываются и учитываются.
    """
    visible = []
    counts = {"critical": 0, "warning": 0, "info": 0}
    hidden_count = 0
    for v in vulns:
        port = _vuln_port(v)
        vkey = db.vuln_state_key(ip, port, v.get("cve_id") or "",
                                 v.get("title") or "")
        strec = states_map.get(vkey)
        vstate = strec["state"] if strec else ""
        v["vkey"] = vkey
        v["vport"] = port
        v["vstate"] = vstate
        if vstate == "hidden":
            hidden_count += 1
            if not show_hidden:
                continue
        visible.append(v)
        sev = v.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return visible, counts, hidden_count


def _build_report_rows(target_id, scan_class="main", show_hidden=False):
    """Собрать строки итоговой таблицы по последнему запуску каждого IP
    в рамках класса сканирования scan_class."""
    states = db.report_rows(target_id, scan_class)
    notes = db.get_ip_notes(target_id)
    attrs = db.get_ip_attributes(target_id)  # {ip: {admins, ctrl_*}}
    origins = db.get_ip_origins(target_id)   # {ip: {'source':..., 'domain':...}}
    vstates = db.get_vuln_states(target_id)  # П.11: состояния скрытия/принятия
    rows = []
    for st in states:
        last_run = st.get("last_run_id")
        ports_disp, services_disp, web_disp = [], [], []
        vulns = []
        vuln_counts = {"critical": 0, "warning": 0, "info": 0}
        hidden_count = 0
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
                raw_vulns = []
                for v in db.vulns_for_host(host["id"]):
                    # Треб. 3б: кликабельная ссылка NVD для CVE-находок.
                    if v.get("cve_id"):
                        v["nvd_url"] = cve_lookup.nvd_link(v["cve_id"])
                    v["run_id"] = last_run  # П.11: для «открыть лог» при принятии
                    raw_vulns.append(v)
                # П.11: скрытые уязвимости по умолчанию не показываем и не считаем.
                vulns, vuln_counts, hidden_count = _apply_vuln_states(
                    raw_vulns, st["ip"], target_id, vstates,
                    show_hidden=show_hidden)
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
            "vuln_hidden_count": hidden_count,  # П.11: число скрытых у этого IP
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


# v1.6.0 (треб. 2): человекочитаемые метки для списка «опции».
_OPT_LABELS = {
    "syn_mode": "Режим SYN",
    "profile": "Профиль тайминга",
    "ports": "Порты (явно)",
    "top_ports": "Top-порты",
    "full_ports": "Все 65535 портов",
    "extra_nse": "NSE-скрипты",
    "do_web": "Web-проверки",
    "advanced_anp": "alive_no_ports advanced check",
    "dig_rdns": "Обратный DNS (dig -x)",
    "dns_brute": "Brute-force поддоменов",
    "cve_online": "Онлайн CVE (OSV)",
    "cve_vulners": "NSE vulners",
    "include_info": "Фиксация инфо-находок",
}
_SYN_MODE_LABELS = {"evasion": "обход SYN-защиты (-sT)", "direct": "без обхода"}


@app.template_filter("optsfull")
def optsfull(options_full_json):
    """v1.6.0 (треб. 2): полный список опций запуска — список пар
    (метка, значение) для раскрывающегося списка «опции»."""
    import json as _json
    if not options_full_json:
        return []
    try:
        o = _json.loads(options_full_json)
    except (ValueError, TypeError):
        return []
    out = []
    for key, label in _OPT_LABELS.items():
        if key not in o:
            continue
        val = o[key]
        if key == "syn_mode":
            val = _SYN_MODE_LABELS.get(val, val)
        elif isinstance(val, bool):
            if not val:
                continue  # выключённые флаги не показываем
            val = "да"
        elif val in (None, ""):
            continue
        out.append((label, str(val)))
    return out


@app.template_filter("modlabel")
def modlabel(module):
    """v1.6.0 (треб. 2, 3): читаемая метка модуля."""
    try:
        import errorsink
        return errorsink.MODULE_LABELS.get(module, module)
    except Exception:  # noqa: BLE001
        return module


@app.template_filter("modstatus")
def modstatus(status):
    """v1.6.0 (треб. 2): читаемый статус модуля (graceful degradation)."""
    return {
        "used": "применён",
        "skipped_missing": "пропущен (не установлен)",
        "skipped_degraded": "пропущен (graceful degradation)",
        "off": "выключён",
    }.get(status, status)


@app.context_processor
def inject_user():
    # v1.6.0 (треб. 4): список активных сканов — для индикатора во вкладках.
    # П.2 (v1.6.5): номер версии — в footer.
    # П.11 (v1.6.5): счётчик принятых уязвимостей — бейдж на вкладке «Разбор».
    try:
        triage_count = db.count_accepted_vulns()
    except Exception:  # noqa: BLE001
        triage_count = 0
    return {"current_user": session.get("user"),
            "running_count": len(_running_all()),
            "triage_count": triage_count,
            "app_version": appversion.get_version()}


if __name__ == "__main__":
    db.init_db()
    host = os.environ.get("NETINV_HOST", "127.0.0.1")
    port = int(os.environ.get("NETINV_PORT", "5000"))
    app.run(host=host, port=port, debug=False, threaded=True)
