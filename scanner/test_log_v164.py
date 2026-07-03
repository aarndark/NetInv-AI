#!/usr/bin/env python3
"""Тесты Правки 3 (v1.6.4): детальное логирование ВСЕХ модулей в файл.

Проверяем, что ScanLogger.detail(module, msg):
  * пишет запись на уровне DEBUG в ФАЙЛ лога (FileHandler=DEBUG);
  * НЕ дублирует её в консоль (StreamHandler=INFO);
  * корректно добавляет метку [module] и разбивает многострочный текст;
  * make_detail_sink(module) возвращает рабочий callback.

Запуск:
    .venv/bin/python scanner/test_log_v164.py
"""
import io
import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logsetup  # noqa: E402


def _make_logger(tmpdir):
    """Создать ScanLogger с логами в tmpdir и перехваченной консолью."""
    os.environ["NETINV_LOG_DIR"] = tmpdir
    slog = logsetup.ScanLogger(run_id="test_v164", echo_console=True)
    # Перехватываем то, что уходит в консоль (StreamHandler).
    fake_console = io.StringIO()
    slog._sh.setStream(fake_console)
    return slog, fake_console


def _read_log(slog):
    slog._fh.flush()
    with open(slog.path, encoding="utf-8") as f:
        return f.read()


def test_detail_writes_to_file():
    with tempfile.TemporaryDirectory() as tmp:
        slog, _ = _make_logger(tmp)
        slog.detail("webscan", "проверка заголовков HTTP")
        content = _read_log(slog)
        slog.close()
        assert "[webscan] проверка заголовков HTTP" in content, \
            "detail не попал в файл лога"
    print("OK  test_detail_writes_to_file")


def test_detail_not_in_console():
    with tempfile.TemporaryDirectory() as tmp:
        slog, console = _make_logger(tmp)
        slog.detail("cve", "сырой ответ CIRCL browse")
        slog._sh.flush()
        console_text = console.getvalue()
        slog.close()
        assert "сырой ответ CIRCL browse" not in console_text, \
            "detail НЕ должен попадать в консоль (StreamHandler=INFO)"
    print("OK  test_detail_not_in_console")


def test_info_goes_to_both():
    with tempfile.TemporaryDirectory() as tmp:
        slog, console = _make_logger(tmp)
        slog.info("обычное информационное сообщение")
        slog._sh.flush()
        console_text = console.getvalue()
        file_text = _read_log(slog)
        slog.close()
        assert "обычное информационное сообщение" in console_text, \
            "info должно попадать в консоль"
        assert "обычное информационное сообщение" in file_text, \
            "info должно попадать в файл"
    print("OK  test_info_goes_to_both")


def test_detail_multiline_and_tag():
    with tempfile.TemporaryDirectory() as tmp:
        slog, _ = _make_logger(tmp)
        slog.detail("dns", "строка 1\nстрока 2\nстрока 3")
        content = _read_log(slog)
        slog.close()
        assert "[dns] строка 1" in content
        assert "[dns] строка 2" in content
        assert "[dns] строка 3" in content, "многострочный detail разбит неверно"
    print("OK  test_detail_multiline_and_tag")


def test_make_detail_sink():
    with tempfile.TemporaryDirectory() as tmp:
        slog, console = _make_logger(tmp)
        sink = slog.make_detail_sink("preflight")
        assert callable(sink), "make_detail_sink должен вернуть callable"
        sink("доступность утилит: nmap OK")
        slog._sh.flush()
        console_text = console.getvalue()
        file_text = _read_log(slog)
        slog.close()
        assert "[preflight] доступность утилит: nmap OK" in file_text, \
            "sink не пишет в файл с меткой модуля"
        assert "доступность утилит" not in console_text, \
            "sink НЕ должен писать в консоль"
    print("OK  test_make_detail_sink")


def test_handler_levels():
    """Явная проверка уровней обработчиков (контракт Правки 3)."""
    with tempfile.TemporaryDirectory() as tmp:
        slog, _ = _make_logger(tmp)
        assert slog._fh.level == logging.DEBUG, \
            "FileHandler должен быть на уровне DEBUG"
        assert slog._sh.level == logging.INFO, \
            "StreamHandler должен быть на уровне INFO"
        slog.close()
    print("OK  test_handler_levels")


if __name__ == "__main__":
    tests = [
        test_detail_writes_to_file,
        test_detail_not_in_console,
        test_info_goes_to_both,
        test_detail_multiline_and_tag,
        test_make_detail_sink,
        test_handler_levels,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    total = len(tests)
    print(f"\n{total - failed}/{total} тестов пройдено")
    sys.exit(1 if failed else 0)
