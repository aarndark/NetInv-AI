#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diff_engine.py — расчёт отличий между запусками сканирования.

Отличия и история ведутся ОТДЕЛЬНО по каждому классу сканирования
(main/advanced): основное сканирование сравнивается только с предыдущими
основными запусками, расширенное — только с расширенными.

После каждого запуска для каждого IP в рамках target (и класса scan_class)
пересчитывается строка в host_state:
    - first_seen        : дата первого ОБНАРУЖЕНИЯ узла (фиксируется один раз)
    - last_run_id       : текущий запуск
    - prev_run_id       : предыдущий завершённый запуск того же класса
    - prev2_run_id      : позапрошлый завершённый запуск того же класса
    - presence          : pres|new|gone — присутствие IP относительно прошлого
                          запуска того же класса (для подсветки):
                            new  — IP не было в прошлом сканировании;
                            gone — IP был, но в текущем отсутствует;
                            pres — обычное присутствие.
    - diff_prev         : отличия текущего состояния от предыдущего (JSON)
    - diff_prev2        : отличия от позапрошлого (JSON)

Структура diff JSON:
    {
      "status":        <строка-статус | отсутствует>,
      "presence":      "pres|new|gone",
      "new_ports":     [список новых портов],         # «Обнаружены новые порты»
      "new_services":  [список новых сервисов],        # «Обнаружены новые сервисы»
      "gone_ports":    [список пропавших портов],       # «Порты ... не обнаружены»
      "gone_services": [список пропавших сервисов],     # «Сервисы ... не обнаружены»
      "added":         [прочие добавления, напр. web],
      "removed":       [прочие удаления],
      "changed":       [изменения]
    }
Поля new_ports/gone_ports/... используются и для текстового примечания
(требования 5–8), и для подсветки в отчёте.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402


def _port_key(p):
    return f"{p['port']}/{p['proto']}"


def _port_repr(p):
    svc = " ".join(x for x in [p.get("service"), p.get("product"),
                               p.get("version")] if x).strip()
    conf = p.get("confidence", "")
    suffix = f" ({conf})" if conf and conf != "confirmed" else ""
    return f"{p['port']}/{p['proto']} {svc}{suffix}".strip()


def _port_label(p):
    """Краткая метка порта для перечисления: «80/tcp»."""
    return f"{p['port']}/{p['proto']}"


def _service_label(p):
    """Метка сервиса для перечисления: «http (80/tcp)» либо «80/tcp»."""
    svc = p.get("service")
    if svc:
        return f"{svc} ({p['port']}/{p['proto']})"
    return f"{p['port']}/{p['proto']}"


def _host_snapshot(run_id, ip):
    """Снимок узла в конкретном запуске: множества портов и web-ресурсов."""
    host = db.host_by_ip_in_run(run_id, ip)
    if not host:
        return None
    ports = db.ports_for_host(host["id"])
    webs = db.webres_for_host(host["id"])
    port_map = {_port_key(p): p for p in ports}
    web_map = {w["url"]: w for w in webs}
    return {"host": host, "port_map": port_map, "web_map": web_map}


def _empty_diff():
    return {
        "new_ports": [], "new_services": [],
        "gone_ports": [], "gone_services": [],
        "added": [], "removed": [], "changed": [],
    }


def _diff_snapshots(cur, old):
    """Вернуть структуру отличий между двумя снимками узла (того же класса)."""
    if cur is None and old is None:
        return None
    result = _empty_diff()

    cur_ports = cur["port_map"] if cur else {}
    old_ports = old["port_map"] if old else {}

    # Новые порты/сервисы (есть сейчас, не было раньше) — требование 7
    for k in sorted(set(cur_ports) - set(old_ports)):
        p = cur_ports[k]
        result["new_ports"].append(_port_label(p))
        if p.get("service"):
            result["new_services"].append(_service_label(p))
    # Пропавшие порты/сервисы (были раньше, нет сейчас) — требование 8
    for k in sorted(set(old_ports) - set(cur_ports)):
        p = old_ports[k]
        result["gone_ports"].append(_port_label(p))
        if p.get("service"):
            result["gone_services"].append(_service_label(p))
    # Изменения в общих портах
    for k in sorted(set(cur_ports) & set(old_ports)):
        a, b = cur_ports[k], old_ports[k]
        if _port_repr(a) != _port_repr(b):
            result["changed"].append(
                f"порт {k}: было «{_port_repr(b)}» → стало «{_port_repr(a)}»")

    # Web-ресурсы (прочие добавления/удаления/изменения)
    cur_web = cur["web_map"] if cur else {}
    old_web = old["web_map"] if old else {}
    for u in sorted(set(cur_web) - set(old_web)):
        w = cur_web[u]
        result["added"].append(
            f"web {u} [{w.get('status_code')}] {w.get('server') or ''}".strip())
    for u in sorted(set(old_web) - set(cur_web)):
        result["removed"].append(f"web {u}")
    for u in sorted(set(cur_web) & set(old_web)):
        a, b = cur_web[u], old_web[u]
        if (a.get("status_code") != b.get("status_code") or
                (a.get("server") or "") != (b.get("server") or "")):
            result["changed"].append(
                f"web {u}: было [{b.get('status_code')}] {b.get('server') or ''} → "
                f"стало [{a.get('status_code')}] {a.get('server') or ''}")

    if not any(result[k] for k in result):
        result["status"] = "без изменений"
    return result


def update_host_states(target_id, current_run_id, scan_class="main"):
    """Пересчитать host_state для IP текущего запуска (в рамках scan_class).

    Сравнение ведётся только с предыдущими запусками ТОГО ЖЕ класса.
    Дополнительно отмечаются:
      - новые IP (есть сейчас, не было в прошлом запуске класса)  → presence='new';
      - пропавшие IP (были в прошлом запуске, нет в текущем)       → presence='gone'.
    """
    cur_run = db.get_run(current_run_id)
    if not cur_run:
        return

    priors = db.prior_run_ids(target_id, current_run_id, n=2, scan_class=scan_class)
    prev_run_id = priors[0] if len(priors) >= 1 else None
    prev2_run_id = priors[1] if len(priors) >= 2 else None

    prev_run = db.get_run(prev_run_id) if prev_run_id else None
    prev2_run = db.get_run(prev2_run_id) if prev2_run_id else None

    cur_hosts = db.hosts_for_run(current_run_id)
    cur_ips = {h["ip"] for h in cur_hosts}
    prev_ips = set()
    if prev_run_id:
        prev_ips = {h["ip"] for h in db.hosts_for_run(prev_run_id)}

    # --- IP, присутствующие в текущем запуске ---
    for host in cur_hosts:
        ip = host["ip"]
        cur_snap = _host_snapshot(current_run_id, ip)
        prev_snap = _host_snapshot(prev_run_id, ip) if prev_run_id else None
        prev2_snap = _host_snapshot(prev2_run_id, ip) if prev2_run_id else None

        # Новый IP, если был предыдущий запуск, но в нём этого IP не было.
        is_new = bool(prev_run_id) and ip not in prev_ips
        presence = "new" if is_new else "pres"

        if not prev_run_id:
            diff_prev = {"status": "первое обнаружение", "presence": "pres"}
        elif is_new:
            diff_prev = _empty_diff()
            diff_prev["status"] = "Обнаружен новый IP"
            diff_prev["presence"] = "new"
            # У нового IP все его порты/сервисы — новые.
            d = _diff_snapshots(cur_snap, None)
            if d:
                for k in ("new_ports", "new_services"):
                    diff_prev[k] = d.get(k, [])
        else:
            diff_prev = _diff_snapshots(cur_snap, prev_snap)
            diff_prev["presence"] = "pres"

        diff_prev2 = _diff_snapshots(cur_snap, prev2_snap) if prev2_run_id else None

        first_seen = db.host_state_first_seen(target_id, scan_class, ip) \
            or host["scanned_at"]

        db.upsert_host_state(
            target_id, scan_class, ip,
            first_seen=first_seen,
            last_run_id=current_run_id,
            prev_run_id=prev_run_id,
            prev2_run_id=prev2_run_id,
            last_scanned_at=cur_run["started_at"],
            prev_scanned_at=prev_run["started_at"] if prev_run else None,
            prev2_scanned_at=prev2_run["started_at"] if prev2_run else None,
            diff_prev=json.dumps(diff_prev, ensure_ascii=False),
            diff_prev2=json.dumps(diff_prev2, ensure_ascii=False) if diff_prev2 else None,
            presence=presence,
        )

    # --- IP, которые были в прошлом запуске, но отсутствуют в текущем ---
    # Требование 6: помечаем как пропавшие, заносим «IP не найден».
    for ip in sorted(prev_ips - cur_ips, key=db.ip_sort_key):
        prev_snap = _host_snapshot(prev_run_id, ip)
        diff_prev = _empty_diff()
        diff_prev["status"] = "IP не найден"
        diff_prev["presence"] = "gone"
        # Все ранее известные порты/сервисы считаем пропавшими.
        if prev_snap:
            d = _diff_snapshots(None, prev_snap)
            if d:
                for k in ("gone_ports", "gone_services"):
                    diff_prev[k] = d.get(k, [])

        first_seen = db.host_state_first_seen(target_id, scan_class, ip)

        db.upsert_host_state(
            target_id, scan_class, ip,
            first_seen=first_seen,
            last_run_id=current_run_id,
            prev_run_id=prev_run_id,
            last_scanned_at=cur_run["started_at"],
            prev_scanned_at=prev_run["started_at"] if prev_run else None,
            diff_prev=json.dumps(diff_prev, ensure_ascii=False),
            presence="gone",
        )


def rebuild_host_states(target_id, scan_class):
    """v1.6.0 (треб. 1): полный пересчёт host_state объекта после
    удаления одного из запусков.

    Очищает все строки host_state данного (target_id, scan_class) и заново
    проигрывает все ОСТАВШИЕСЯ запуски класса в хронологическом
    порядке через update_host_states(). Так как prior_run_ids() читает
    текущее содержимое scan_runs, цепочки prev/prev2 и diff-ы
    восстанавливаются корректно без учёта удалённого запуска.
    """
    db.clear_host_state(target_id, scan_class)
    for run_id in db.run_ids_asc(target_id, scan_class):
        update_host_states(target_id, run_id, scan_class=scan_class)


def diff_to_text(diff_json):
    """Человекочитаемое представление diff для таблицы (требования 5–8)."""
    if not diff_json:
        return "—"
    try:
        d = json.loads(diff_json)
    except (json.JSONDecodeError, TypeError):
        return str(diff_json)
    if not isinstance(d, dict):
        return str(diff_json)

    parts = []

    presence = d.get("presence")
    if presence == "new":
        parts.append("Обнаружен новый IP")
    elif presence == "gone":
        parts.append("IP не найден")
    elif d.get("status") and d["status"] not in ("Обнаружен новый IP", "IP не найден"):
        # «первое обнаружение» / «без изменений» — только если нет иных отличий
        if not any(d.get(k) for k in
                   ("new_ports", "new_services", "gone_ports", "gone_services",
                    "added", "removed", "changed")):
            return d["status"]

    # Требование 7: новые порты / новые сервисы
    if d.get("new_ports"):
        parts.append("Обнаружены новые порты " + ", ".join(d["new_ports"]))
    if d.get("new_services"):
        parts.append("Обнаружены новые сервисы " + ", ".join(d["new_services"]))
    # Требование 8: пропавшие порты / сервисы
    if d.get("gone_ports"):
        parts.append("Порты " + ", ".join(d["gone_ports"]) + " не обнаружены")
    if d.get("gone_services"):
        parts.append("Сервисы " + ", ".join(d["gone_services"]) + " не обнаружены")

    # Прочее (web и изменения)
    for item in d.get("added", []):
        parts.append("➕ " + item)
    for item in d.get("removed", []):
        parts.append("➖ " + item)
    for item in d.get("changed", []):
        parts.append("✎ " + item)

    if not parts:
        return "без изменений"
    return "; ".join(parts)


def diff_to_lines(diff_json):
    """То же, что diff_to_text, но возвращает СПИСОК блоков отличий (треб. 1а).

    Каждый элемент — отдельный блок отличия, чтобы в таблице выводить их
    построчно (а не одной строкой через «; »). Для пустого/без изменений
    возвращается список из одного элемента.
    """
    text = diff_to_text(diff_json)
    if text in ("—", "без изменений") or not text:
        return [text or "—"]
    # Спец-статусы без разделителей возвращаем как один блок.
    if "; " not in text:
        return [text]
    return [p for p in text.split("; ") if p]


def diff_flags(diff_json):
    """Флаги подсветки для отчёта по строке IP.

    Возвращает dict:
      presence_new / presence_gone — подсветка строки/IP (требования 5–6);
      has_new_ports                — есть новые порты/сервисы (требование 7);
      has_gone_ports               — есть пропавшие порты/сервисы (требование 8).
    """
    flags = {"presence_new": False, "presence_gone": False,
             "has_new_ports": False, "has_gone_ports": False}
    if not diff_json:
        return flags
    try:
        d = json.loads(diff_json)
    except (json.JSONDecodeError, TypeError):
        return flags
    if not isinstance(d, dict):
        return flags
    presence = d.get("presence")
    flags["presence_new"] = presence == "new"
    flags["presence_gone"] = presence == "gone"
    flags["has_new_ports"] = bool(d.get("new_ports") or d.get("new_services"))
    flags["has_gone_ports"] = bool(d.get("gone_ports") or d.get("gone_services"))
    return flags
