"""Управление активными сканами: приостановка и отмена (v1.6.1, правка 1).

Кооперативный механизм: сам сканер периодически спрашивает объект
``ScanControl`` о том, нужно ли приостановиться или отмениться. Длинные
внешние процессы (nmap) дополнительно приостанавливаются/убиваются на
уровне ОС через сигналы группе процессов (POSIX: SIGSTOP/SIGCONT/SIGTERM).

Дизайн намеренно простой и потокобезопасный:

* ``request_pause()``  — пометить, что скан должен встать на паузу;
* ``request_resume()`` — снять паузу;
* ``request_cancel()`` — пометить, что скан должен корректно прерваться;
* ``checkpoint()``     — вызывается сканером между этапами: блокирует
  поток на время паузы и бросает ``ScanCancelled`` при отмене;
* ``attach_proc()`` / ``detach_proc()`` — регистрируют текущий дочерний
  процесс (nmap и т.п.), чтобы пауза/отмена действовали и на него.

Всё graceful: если сигналы недоступны (не-POSIX), пауза сводится к
задержке между этапами, а отмена — к прекращению после текущего этапа.
"""

from __future__ import annotations

import os
import signal
import threading


class ScanCancelled(Exception):
    """Бросается из checkpoint(), когда скан отменён оператором."""


# Статусы для отображения в UI.
STATE_RUNNING = "running"
STATE_PAUSED = "paused"
STATE_CANCELLING = "cancelling"

# П.3 (v1.6.5): фазы сканирования для полосы прогресса в «Текущем».
# Порядок соответствует ходу run_scan: DNS-разведка → nmap → web-проверки.
PHASE_DNS = "dns"
PHASE_NMAP = "nmap"
PHASE_WEB = "webscan"
PHASE_DONE = "done"
# Полный порядок фаз (для отрисовки сегментов слева направо).
PHASE_ORDER = [PHASE_DNS, PHASE_NMAP, PHASE_WEB]
# Человекочитаемые метки (RU) для UI.
PHASE_LABELS = {
    PHASE_DNS: "DNS-разведка",
    PHASE_NMAP: "nmap-сканирование",
    PHASE_WEB: "Web-проверки",
    PHASE_DONE: "Завершение",
}


class ScanControl:
    """Флаги управления одним активным сканом (потокобезопасно)."""

    def __init__(self):
        self._lock = threading.Lock()
        # pause: когда сброшен (clear) — скан на паузе; установлен (set) — идёт.
        self._resume = threading.Event()
        self._resume.set()
        self._cancel = threading.Event()
        self._paused_flag = False
        self._procs = []  # активные дочерние процессы (subprocess.Popen)
        # П.3: текущая фаза скана (для полосы прогресса). None до старта.
        self._phase = None

    # ---- запросы оператора (из веб-потока) ----

    def request_pause(self):
        with self._lock:
            self._resume.clear()
            self._paused_flag = True
            self._signal_procs(signal.SIGSTOP)

    def request_resume(self):
        with self._lock:
            self._paused_flag = False
            self._signal_procs(signal.SIGCONT)
            self._resume.set()

    def request_cancel(self):
        with self._lock:
            self._cancel.set()
            # Снимаем возможную паузу, чтобы поток дошёл до checkpoint().
            self._resume.set()
            # Возобновляем (на случай, если процесс был остановлен), затем убьём.
            self._signal_procs(signal.SIGCONT)
            self._signal_procs(signal.SIGTERM)

    # ---- состояние (для UI) ----

    def state(self):
        with self._lock:
            if self._cancel.is_set():
                return STATE_CANCELLING
            if self._paused_flag:
                return STATE_PAUSED
            return STATE_RUNNING

    def is_cancelled(self):
        return self._cancel.is_set()

    def is_paused(self):
        with self._lock:
            return self._paused_flag

    # ---- П.3: фаза скана (для полосы прогресса) ----

    def set_phase(self, phase):
        """Пометить текущую фазу скана (dns|nmap|webscan|done)."""
        with self._lock:
            self._phase = phase

    def phase(self):
        """Текущая фаза скана (или None, если ещё не начата)."""
        with self._lock:
            return self._phase

    # ---- точки взаимодействия из сканера ----

    def checkpoint(self):
        """Вызывается сканером между этапами.

        Блокирует поток, пока действует пауза; при отмене бросает
        ScanCancelled, чтобы сканер корректно завершил запуск.
        """
        if self._cancel.is_set():
            raise ScanCancelled()
        # Ждём снятия паузы (без активного цикла); просыпаемся при resume/cancel.
        while not self._resume.wait(timeout=0.5):
            if self._cancel.is_set():
                raise ScanCancelled()
        if self._cancel.is_set():
            raise ScanCancelled()

    def attach_proc(self, proc):
        """Зарегистрировать дочерний процесс (nmap и т.п.)."""
        with self._lock:
            self._procs.append(proc)
            # Если уже на паузе — сразу останавливаем новый процесс.
            if self._paused_flag:
                self._signal_one(proc, signal.SIGSTOP)
            if self._cancel.is_set():
                self._signal_one(proc, signal.SIGTERM)

    def detach_proc(self, proc):
        with self._lock:
            try:
                self._procs.remove(proc)
            except ValueError:
                pass

    # ---- внутреннее: сигналы процессам ----

    def _signal_procs(self, sig):
        for p in list(self._procs):
            self._signal_one(p, sig)

    @staticmethod
    def _signal_one(proc, sig):
        """Послать сигнал процессу (по возможности — всей группе процессов)."""
        if proc is None or proc.poll() is not None:
            return
        try:
            # Процесс запущен в своей группе (start_new_session=True) —
            # сигналим всей группе, чтобы затронуть дочерние nmap-процессы.
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            # Фоллбек: сигнал самому процессу.
            try:
                proc.send_signal(sig)
            except (ProcessLookupError, OSError):
                pass
