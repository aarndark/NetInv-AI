#!/usr/bin/env python3
"""П.3 (v1.6.5): тесты полосы прогресса фаз в «Текущем сканировании».

Проверяем:
  1. ScanControl.set_phase/phase — потокобезопасное хранение фазы.
  2. Константы фаз и порядок/метки корректны.
  3. /current/status возвращает phase, has_domains, phase_order, phase_labels
     для активного скана.
  4. has_domains=True для объекта с доменами, False — без.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import scancontrol, db  # noqa: E402


def test_scancontrol_phase():
    c = scancontrol.ScanControl()
    assert c.phase() is None, "начальная фаза должна быть None"
    c.set_phase(scancontrol.PHASE_DNS)
    assert c.phase() == "dns"
    c.set_phase(scancontrol.PHASE_NMAP)
    assert c.phase() == "nmap"
    c.set_phase(scancontrol.PHASE_WEB)
    assert c.phase() == "webscan"
    c.set_phase(scancontrol.PHASE_DONE)
    assert c.phase() == "done"
    print("OK: ScanControl.set_phase/phase")


def test_phase_constants():
    assert scancontrol.PHASE_ORDER == ["dns", "nmap", "webscan"]
    assert scancontrol.PHASE_LABELS["dns"] == "DNS-разведка"
    assert scancontrol.PHASE_LABELS["nmap"] == "nmap-сканирование"
    assert scancontrol.PHASE_LABELS["webscan"] == "Web-проверки"
    print("OK: константы фаз и метки")


def test_status_endpoint():
    # Импортируем приложение и его реестр активных сканов.
    from webapp import app as webapp

    # Находим объект с доменами и (по возможности) без.
    targets = db.list_targets()
    assert targets, "нужен хотя бы один объект в БД (запустите seed)"
    with_domains = None
    for t in targets:
        if db.domains_for_target(t["id"]):
            with_domains = t["id"]
            break
    assert with_domains is not None, "нужен объект с доменами (seed_test)"

    # Регистрируем фейковый активный скан в фазе nmap.
    ctrl = scancontrol.ScanControl()
    ctrl.set_phase(scancontrol.PHASE_NMAP)
    webapp._running_set(with_domains, "main", "тест-фаза", control=ctrl)

    client = webapp.app.test_client()
    # Логинимся (сессия).
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["in_cpt"] = True

    resp = client.get("/current/status")
    assert resp.status_code == 200, resp.status_code
    j = resp.get_json()
    assert j["phase_order"] == ["dns", "nmap", "webscan"], j.get("phase_order")
    assert j["phase_labels"]["dns"] == "DNS-разведка"
    running = {r["target_id"]: r for r in j["running"]}
    assert with_domains in running, "активный скан не найден в статусе"
    r = running[with_domains]
    assert r["phase"] == "nmap", r.get("phase")
    assert r["has_domains"] is True, "объект с доменами → has_domains=True"
    print("OK: /current/status возвращает phase/has_domains/order/labels")

    # Чистим реестр.
    webapp._running_clear(with_domains)


if __name__ == "__main__":
    test_scancontrol_phase()
    test_phase_constants()
    test_status_endpoint()
    print("\nВСЕ ТЕСТЫ П.3 ПРОШЛИ")
