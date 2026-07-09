#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""appversion.py — единый источник номера версии NetInv (v1.6.5, П.2).

Читает файл ``VERSION`` из корня проекта. Используется:
  * CLI-ключом ``-version``/``--version`` (scanner.py, run_cron.py);
  * веб-интерфейсом (footer через context processor).

Хелпер вынесен отдельно, чтобы номер версии не дублировался в коде.
"""
import os

# Корень проекта = каталог на уровень выше scanner/.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VERSION_FILE = os.path.join(_PROJECT_ROOT, "VERSION")


def get_version():
    """Вернуть номер версии из файла VERSION (без завершающих пробелов).

    При отсутствии/ошибке чтения файла возвращает ``"unknown"`` — CLI и UI
    должны деградировать мягко, а не падать.
    """
    try:
        with open(_VERSION_FILE, encoding="utf-8") as f:
            v = f.read().strip()
        return v or "unknown"
    except OSError:
        return "unknown"


def version_string():
    """Строка для вывода в CLI: ``NetInv 1.6.5``."""
    return f"NetInv {get_version()}"


if __name__ == "__main__":
    print(version_string())
