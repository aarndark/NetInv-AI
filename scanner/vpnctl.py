#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vpnctl.py — управление AdGuard VPN для онлайн-запросов CVE (v1.6.2).

НАЗНАЧЕНИЕ (по согласованию с пользователем):

  Прямой egress к api.osv.dev из сети объекта заблокирован (и IPv4, и IPv6
  дают таймаут подключения). Доступ появляется только через VPN. Сканировать
  собственную подсеть с постоянно включённым VPN нельзя — трафик пойдёт не
  туда. Поэтому VPN поднимается ТОЛЬКО на фазу онлайн-CVE и сразу отключается.

МОДЕЛЬ РАБОТЫ:

  - Одна VPN-сессия на всю фазу CVE скана (а не на каждый запрос).
  - Управление через `adguardvpn-cli connect/disconnect` (требует sudo).
  - Счётчик ссылок (reference counting) + блокировка: несколько параллельных
    сканов в одном процессе Flask совместно используют один туннель и не
    гасят его, пока хоть один скан ещё в фазе CVE.
  - GRACEFUL DEGRADATION: если adguardvpn-cli не установлен, нет sudo без
    пароля, VPN не поднялся — фаза CVE просто пропускается онлайн, работает
    offline-таблица. Скан НЕ падает.
  - Если задан прокси (NETINV_HTTPS_PROXY) — VPN не трогаем: считаем, что
    оператор сам обеспечил маршрут к OSV.

ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ:

  NETINV_OSV_VPN=1|0            включить/выключить авто-VPN (по умолч. 1)
  NETINV_OSV_VPN_LOCATION=...   локация AdGuard (по умолч. Helsinki)
  NETINV_OSV_VPN_BIN=...        путь к adguardvpn-cli (по умолч. из PATH)
  NETINV_OSV_VPN_SUDO=1|0       использовать sudo (по умолч. 1)
  NETINV_HTTPS_PROXY=...        если задан — VPN НЕ поднимается (см. выше)
"""

import os
import shutil
import subprocess
import threading

# --- Конфигурация из окружения ------------------------------------------
DEFAULT_LOCATION = "Helsinki"
_CONNECT_TIMEOUT = 60          # сек на установку соединения
_DISCONNECT_TIMEOUT = 30       # сек на отключение
_STATUS_TIMEOUT = 15


def _enabled():
    """Включён ли авто-VPN. Если задан прокси — считаем, что маршрут уже есть."""
    if os.environ.get("NETINV_HTTPS_PROXY") or os.environ.get("HTTPS_PROXY") \
            or os.environ.get("https_proxy"):
        return False
    return os.environ.get("NETINV_OSV_VPN", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _location():
    return (os.environ.get("NETINV_OSV_VPN_LOCATION") or DEFAULT_LOCATION).strip()


def _bin():
    return (os.environ.get("NETINV_OSV_VPN_BIN")
            or shutil.which("adguardvpn-cli")
            or "adguardvpn-cli")


def _use_sudo():
    return os.environ.get("NETINV_OSV_VPN_SUDO", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _cmd(*args):
    """Собрать команду adguardvpn-cli (с sudo -n при необходимости)."""
    base = []
    if _use_sudo() and os.geteuid() != 0:
        # -n: НЕ спрашивать пароль интерактивно (в фоне скана это повесит
        # процесс). Требуется настроенный NOPASSWD sudoers или запуск от root.
        base = ["sudo", "-n"]
    return base + [_bin(), *args]


def available():
    """Установлен ли adguardvpn-cli в системе."""
    return bool(shutil.which(_bin()) or os.path.isfile(_bin()))


# --- Состояние сессии (reference counting) -------------------------------
_lock = threading.RLock()
_refcount = 0                  # сколько сканов сейчас в фазе CVE
_active = False                # поднят ли туннель нами
_failed = False               # была ли неустранимая ошибка (не долбить повторно)


def _run(cmd, timeout, log):
    """Выполнить команду VPN-CLI, вернуть (ok, stdout+stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        return p.returncode == 0, out
    except FileNotFoundError:
        return False, "adguardvpn-cli не найден"
    except subprocess.TimeoutExpired:
        return False, f"превышен таймаут ({timeout}с)"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def is_connected(log=None):
    """Проверить статус VPN (best-effort)."""
    ok, out = _run(_cmd("status"), _STATUS_TIMEOUT, log)
    if not ok:
        return False
    low = out.lower()
    return "connected" in low and "disconnected" not in low.split("connected")[0]


def begin_cve_phase(log=None):
    """Поднять VPN на фазу онлайн-CVE (idempotent, с учётом счётчика ссылок).

    Возвращает True, если онлайн-CVE можно выполнять (VPN поднят ИЛИ авто-VPN
    отключён и оператор сам обеспечил маршрут). False → онлайн-CVE пропустить.
    """
    def _log(m):
        if log:
            log("[vpn] " + m)

    if not _enabled():
        # Прокси задан или авто-VPN выключен — маршрут обеспечивает оператор.
        _log("авто-VPN отключён (задан прокси или NETINV_OSV_VPN=0) — "
             "использую текущий маршрут к OSV.")
        return True

    global _refcount, _active, _failed
    with _lock:
        if not available():
            _log("adguardvpn-cli не установлен — онлайн-CVE через VPN "
                 "недоступны, работает offline-таблица (graceful).")
            _failed = True
            return False
        if _active:
            _refcount += 1
            _log(f"VPN уже поднят, переиспользую (сессий CVE: {_refcount}).")
            return True
        if _failed:
            # Прошлая попытка в этом процессе провалилась — не долбим повторно.
            return False

        loc = _location()
        _log(f"поднимаю AdGuard VPN (локация: {loc}) на фазу онлайн-CVE ...")
        ok, out = _run(_cmd("connect", "-l", loc), _CONNECT_TIMEOUT, log)
        if not ok:
            _failed = True
            hint = ""
            if "sudo" in out.lower() or "password" in out.lower():
                hint = (" Похоже, нужен пароль sudo. Настройте NOPASSWD для "
                        "adguardvpn-cli в sudoers или запустите скан от root, "
                        "либо задайте NETINV_HTTPS_PROXY.")
            _log(f"НЕ удалось поднять VPN: {out}.{hint} "
                 "Онлайн-CVE пропускаются (offline-таблица работает).")
            return False
        _active = True
        _refcount = 1
        _log(f"VPN поднят (локация: {loc}) — онлайн-CVE через api.osv.dev "
             "включены.")
        return True


def end_cve_phase(log=None):
    """Завершить фазу CVE: опустить счётчик, при нуле — отключить VPN.

    Вызывается в finally скана, поэтому НИКОГДА не бросает исключений.
    """
    def _log(m):
        if log:
            log("[vpn] " + m)

    if not _enabled():
        return
    global _refcount, _active
    try:
        with _lock:
            if not _active:
                return
            _refcount = max(0, _refcount - 1)
            if _refcount > 0:
                _log(f"фаза CVE завершена, но ещё активны сессии: {_refcount} "
                     "— VPN оставляю поднятым.")
                return
            _log("фаза CVE завершена — отключаю VPN ...")
            ok, out = _run(_cmd("disconnect"), _DISCONNECT_TIMEOUT, log)
            _active = False
            if ok:
                _log("VPN отключён, штатный маршрут восстановлен.")
            else:
                _log(f"предупреждение: команда отключения VPN вернула ошибку: "
                     f"{out}. Проверьте статус вручную: adguardvpn-cli status.")
    except Exception as e:  # noqa: BLE001
        _log(f"исключение при отключении VPN подавлено: {e}")


def force_disconnect(log=None):
    """Аварийное отключение VPN (например, при завершении процесса)."""
    def _log(m):
        if log:
            log("[vpn] " + m)
    global _refcount, _active
    try:
        with _lock:
            if not _active:
                return
            _run(_cmd("disconnect"), _DISCONNECT_TIMEOUT, log)
            _active = False
            _refcount = 0
            _log("аварийное отключение VPN выполнено.")
    except Exception:  # noqa: BLE001
        pass
