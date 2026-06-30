#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logsetup.py — подробное логирование сканирований NetInv (требование 5 v1.4.0).

Каждый запуск сканирования (scanner.run_scan) ведёт ОТДЕЛЬНЫЙ подробный файл
лога, куда пишется весь ход операции: команды nmap, DNS-разведка, выявление
web-ресурсов, какие утилиты запущены/пропущены, найденные уязвимости и CVE,
ошибки и предупреждения.

КАТАЛОГ ЛОГОВ
-------------
По умолчанию — /opt/netinv/logs (как просил пользователь). Если каталог
недоступен для записи (например, NetInv запущен не из /opt или без прав),
выполняется аккуратный фолбэк в <корень проекта>/logs. Путь можно явно
переопределить переменной окружения NETINV_LOG_DIR.

ИМЯ ФАЙЛА
---------
netinv_YYMMDD_TIME.log, где YYMMDD — дата, TIME — HHMMSS.
Пример: netinv_260623_115530.log

ВЫВОД
-----
Логгер настроен на ДВА обработчика:
  1. FileHandler  — подробный лог в файл (уровень DEBUG).
  2. StreamHandler(stdout) — дублирование в консоль, где запущен netinv
     (требование 7): пользователь видит ход сканирования в реальном времени.
"""

import datetime as dt
import getpass
import logging
import os
import subprocess
import sys

# Каталог логов по умолчанию (требование 5).
DEFAULT_LOG_DIR = "/opt/netinv/logs"


def _project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _diag_dir(path):
    """Короткая диагностика почему каталог недоступен для записи.

    Возвращает человекочитаемую строку с владельцем/правами и подсказкой,
    как починить. Нужна именно для типичного случая: /opt/netinv/logs
    создан root, а web/cron NetInv работают от обычного пользователя.
    """
    try:
        cur_user = getpass.getuser()
    except Exception:  # noqa: BLE001
        cur_user = str(os.getuid()) if hasattr(os, "getuid") else "?"
    if not os.path.exists(path):
        return (f"каталог не существует и не создаётся (пользователь {cur_user!r}); "
                f"создайте: sudo mkdir -p {path} && sudo chown -R {cur_user} {path}")
    try:
        st = os.stat(path)
        import grp
        import pwd
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        mode = oct(st.st_mode & 0o777)
    except Exception:  # noqa: BLE001
        owner = group = mode = "?"
    return (f"нет прав на запись: владелец {owner}:{group} права {mode}, "
            f"а NetInv запущен от {cur_user!r}; "
            f"почините: sudo chown -R {cur_user} {path}")


def resolve_log_dir():
    """Определить рабочий каталог логов с учётом прав и фолбэка.

    Порядок кандидатов (без дубликатов):
      1. NETINV_LOG_DIR (если задан в окружении);
      2. /opt/netinv/logs (по умолчанию);
      3. <корень проекта>/logs (фолбэк, если отличается от п.2);
      4. /tmp/netinv_logs (последний рубеж).

    ВАЖНО: раньше, если проект стоял в /opt/netinv, фолбэк
    <корень>/logs совпадал с /opt/netinv/logs — тот же недоступный
    путь, и логи «молча» уходили в /tmp. Теперь дубликаты
    исключаются, а причина недоступности объясняется явно.

    Возвращает (путь, использован_ли_фолбэк, сообщение_или_None).
    """
    env_dir = os.environ.get("NETINV_LOG_DIR")
    primary = env_dir or DEFAULT_LOG_DIR
    fallback = os.path.join(_project_root(), "logs")

    # Порядок кандидатов без повторов (фолбэк может совпадать с primary).
    candidates = [primary]
    if os.path.abspath(fallback) != os.path.abspath(primary):
        candidates.append(fallback)

    diag = []  # накапливаем причины недоступности каждого кандидата
    for path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            diag.append(f"{path}: нельзя создать ({e})")
            continue
        if os.access(path, os.W_OK | os.X_OK):
            used_fallback = (os.path.abspath(path) != os.path.abspath(primary))
            msg = None
            if used_fallback:
                why = "; ".join(diag) if diag else "основной каталог недоступен"
                msg = (f"Каталог логов по умолчанию ({primary}) недоступен "
                       f"[{why}] — используется фолбэк: {path}")
            return path, used_fallback, msg
        diag.append(f"{path}: {_diag_dir(path)}")

    # Совсем ничего не получилось — последний фолбэк во временный каталог.
    tmp = os.path.join("/tmp", "netinv_logs")
    os.makedirs(tmp, exist_ok=True)
    why = "; ".join(diag) if diag else "неизвестно"
    return tmp, True, (f"Ни основной ({primary}), ни фолбэк-каталог недоступны "
                       f"[{why}]; логи пишутся во временный {tmp}")


def log_filename(when=None):
    """Имя файла лога формата netinv_YYMMDD_TIME.log (требование 5)."""
    when = when or dt.datetime.now()
    return when.strftime("netinv_%y%m%d_%H%M%S.log")


class ScanLogger:
    """Обёртка над logging.Logger для одного запуска сканирования.

    Использование:
        slog = ScanLogger(run_id=42)
        slog.info("Запуск nmap ...")
        slog.tool_output("nmap", proc.stdout)   # сырой вывод утилиты
        slog.close()
    """

    def __init__(self, run_id=None, echo_console=True, when=None):
        self.log_dir, self.used_fallback, self.dir_msg = resolve_log_dir()
        self.filename = log_filename(when)
        self.path = os.path.join(self.log_dir, self.filename)
        self.run_id = run_id

        # Уникальное имя логгера на запуск, чтобы обработчики не дублировались.
        logger_name = f"netinv.scan.{run_id or id(self)}"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        # На случай повторной инициализации — снимаем старые обработчики.
        for h in list(self.logger.handlers):
            self.logger.removeHandler(h)

        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

        self._fh = logging.FileHandler(self.path, encoding="utf-8")
        self._fh.setLevel(logging.DEBUG)
        self._fh.setFormatter(fmt)
        self.logger.addHandler(self._fh)

        self._sh = None
        if echo_console:
            self._sh = logging.StreamHandler(sys.stdout)
            self._sh.setLevel(logging.INFO)
            self._sh.setFormatter(fmt)
            self.logger.addHandler(self._sh)

        # Громкое, непропускаемое сообщение о РЕАЛЬНОМ расположении лога.
        # Раньше при фолбэке пользователь не понимал, куда делись логи
        # (искал в /opt/netinv/logs, а они были в /tmp). Теперь всё явно.
        if self.dir_msg:
            self.logger.warning(self.dir_msg)
        self.logger.info("Файл лога сканирования: %s", self.path)
        # Указатель на последний лог — чтобы его всегда можно было найти,
        # даже если сработал фолбэк. Пишем в два места (без фатальных ошибок):
        # рядом с самим логом и в <корень проекта>/logs.
        self._write_pointer()

    def _write_pointer(self):
        """Записать файл-указатель LAST_LOG_PATH с абсолютным путём лога.

        Даёт пользователю надёжный способ узнать, где лог: даже если
        основной каталог недоступен, указатель в <корень>/logs или
        рядом с логом всё равно подскажет фактический путь.
        """
        targets = {self.log_dir, os.path.join(_project_root(), "logs")}
        for d in targets:
            try:
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "LAST_LOG_PATH"), "w",
                          encoding="utf-8") as f:
                    f.write(self.path + "\n")
            except OSError:
                pass  # нефатально — указатель просто не создаётся здесь

    # --- удобные уровни ----------------------------------------------------
    def debug(self, msg, *a):
        self.logger.debug(msg, *a)

    def info(self, msg, *a):
        self.logger.info(msg, *a)

    def warning(self, msg, *a):
        self.logger.warning(msg, *a)

    def error(self, msg, *a):
        self.logger.error(msg, *a)

    def log(self, msg):
        """Совместимость с callback-стилем log('строка') в модулях сканера."""
        self.logger.info("%s", msg)

    def tool_output(self, tool, output, level=logging.DEBUG):
        """Записать сырой stdout/stderr утилиты (nmap/whatweb/nikto/...).

        В файл пишется целиком (DEBUG); в консоль построчные хвосты не дублируем,
        чтобы не зашумлять, — за реальный поток консоли отвечает scanner.py,
        который запускает утилиты с прямым выводом (требование 7).
        """
        if not output:
            return
        head = f"----- вывод {tool} -----"
        self.logger.log(level, head)
        for line in str(output).splitlines():
            self.logger.log(level, "  %s", line)
        self.logger.log(level, "----- конец вывода %s -----", tool)

    def section(self, title):
        self.logger.info("=" * 8 + " " + title + " " + "=" * 8)

    def close(self):
        for h in (self._fh, self._sh):
            if h is not None:
                try:
                    h.flush()
                    h.close()
                except Exception:  # noqa: BLE001
                    pass
                self.logger.removeHandler(h)


# ==========================================================================
# Требование 7: запуск утилит с ПОТОКОВЫМ выводом stdout в консоль и лог.
# ==========================================================================
# scanner.py раньше запускал nmap/whatweb/nikto через subprocess.run(
#   capture_output=True), то есть вывод появлялся только ПОСЛЕ завершения.
# Теперь утилиты запускаются через run_streamed(): строки stdout/stderr
# печатаются в консоль ПО МЕРЕ ПОЯВЛЕНИЯ (реальное время) и одновременно
# пишутся в файл лога. Это позволяет видеть ход работы nmap и других утилит
# прямо в терминале, где запущен netinv.


def run_streamed(cmd, timeout=None, slog=None, echo=True, label=None,
                 capture=True):
    """Запустить внешнюю команду с потоковым выводом в консоль и лог.

    cmd     — список аргументов команды (как для subprocess);
    timeout — общий таймаут в секундах (None — без ограничения);
    slog    — экземпляр ScanLogger (или None) для записи строк в файл лога;
    echo    — печатать ли строки в консоль (stdout) в реальном времени;
    label   — короткая метка процесса для префикса строк (например, 'nmap');
    capture — сохранять ли весь вывод и вернуть его строкой.

    Возвращает объект с атрибутами .returncode и .stdout (как у
    subprocess.CompletedProcess), чтобы оставаться совместимым с прежним кодом.
    stderr объединён в общий поток (печатается и логируется вместе с stdout).
    """
    import time as _time

    label = label or (os.path.basename(cmd[0]) if cmd else "proc")
    prefix = f"    [{label}] "
    collected = []

    def _emit(line):
        line = line.rstrip("\n")
        if echo:
            # Прямой вывод в консоль с префиксом утилиты.
            sys.stdout.write(prefix + line + "\n")
            sys.stdout.flush()
        if slog is not None:
            # В файл лога — без дублирования в консоль (echo уже сделан выше),
            # поэтому пишем напрямую в файловый обработчик через debug-уровень.
            slog.logger.debug("%s%s", prefix, line)
        if capture:
            collected.append(line)

    if slog is not None:
        slog.logger.info("Запуск: %s", " ".join(cmd))
    elif echo:
        sys.stdout.write(prefix + "запуск: " + " ".join(cmd) + "\n")
        sys.stdout.flush()

    start = _time.time()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
    except FileNotFoundError as e:
        if slog is not None:
            slog.error("Не удалось запустить %s: %s", label, e)
        return subprocess.CompletedProcess(cmd, 127, "")

    try:
        for line in iter(proc.stdout.readline, ""):
            _emit(line)
            if timeout is not None and (_time.time() - start) > timeout:
                proc.kill()
                msg = f"превышен таймаут {timeout}s — процесс {label} остановлен"
                if slog is not None:
                    slog.warning(msg)
                elif echo:
                    sys.stdout.write(prefix + msg + "\n")
                break
    finally:
        try:
            proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()

    return subprocess.CompletedProcess(
        cmd, proc.returncode if proc.returncode is not None else -1,
        "\n".join(collected) if capture else "")


def where_logs():
    """Диагностика путей логов: куда будут писаться логи и почему.

    Выводит в stdout человекочитаемый отчёт. Используется командой
    `netinv logpath` / `scanner.py --where-logs` для быстрой проверки,
    почему логи не появляются в /opt/netinv/logs.
    """
    primary = os.environ.get("NETINV_LOG_DIR") or DEFAULT_LOG_DIR
    fallback = os.path.join(_project_root(), "logs")
    path, used_fallback, msg = resolve_log_dir()
    print("=== Диагностика каталога логов NetInv ===")
    try:
        print("Пользователь запуска:", getpass.getuser())
    except Exception:  # noqa: BLE001
        pass
    print("Корень проекта:  ", _project_root())
    print("NETINV_LOG_DIR:", os.environ.get("NETINV_LOG_DIR") or "(не задан)")
    print("Основной (по умолч.):", primary,
          "->", _diag_dir(primary) if not os.access(primary, os.W_OK | os.X_OK)
          else "доступен для записи")
    if os.path.abspath(fallback) != os.path.abspath(primary):
        print("Фолбэк (проект):  ", fallback,
              "->", _diag_dir(fallback)
              if not os.access(fallback, os.W_OK | os.X_OK)
              else "доступен для записи")
    else:
        print("Фолбэк (проект):   совпадает с основным")
    print("---")
    print("ФАКТИЧЕСКИЙ каталог логов:", path,
          "(ФОЛБЭК!)" if used_fallback else "")
    if msg:
        print("Причина:", msg)
    return path, used_fallback, msg


if __name__ == "__main__":
    if "--where-logs" in sys.argv or "logpath" in sys.argv:
        where_logs()
    else:
        sl = ScanLogger(run_id=0)
        sl.section("ТЕСТ")
        sl.info("Проверка логирования")
        sl.tool_output("echo", "строка 1\nстрока 2")
        sl.close()
        print("Лог записан:", sl.path)
