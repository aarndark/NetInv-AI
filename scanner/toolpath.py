#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
toolpath.py — единый поиск внешних утилит (требование 2 v1.5.0).

ПРОБЛЕМА. Стандартный `shutil.which(name)` ищет бинарник только в каталогах
переменной окружения PATH текущего процесса. Утилиты, установленные не через
apt, часто кладут бинарник в каталог, которого нет в PATH у процесса NetInv —
особенно когда сканер запущен из web/cron под отдельным пользователем:

  * `go install github.com/hahwul/dalfox/v2@latest`  -> ~/go/bin/dalfox
    (а у root — /root/go/bin/dalfox; под www-data — вообще другой $HOME);
  * `snap install dalfox`                              -> /snap/bin/dalfox;
  * ручная сборка                                      -> /usr/local/bin/...

Из-за этого dalfox, успешно отвечающий на `dalfox -h` в интерактивной оболочке,
помечался в NetInv как «недоступный».

РЕШЕНИЕ. `which(name)` ниже сначала пробует штатный PATH, а затем — расширенный
список типовых каталогов установки (go/bin для разных пользователей, snap,
/usr/local/bin и т.п.). Дополнительно эти каталоги однократно добавляются в
os.environ["PATH"] процесса (augment_path), чтобы и сам запуск подхватывал их.
"""

import os
import shutil

# Дополнительные каталоги, где могут лежать бинарники, установленные НЕ через apt.
# Порядок не критичен: which() возвращает первый найденный.
def _extra_dirs():
    dirs = []
    home = os.path.expanduser("~")
    gopath = os.environ.get("GOPATH", "")
    gobin = os.environ.get("GOBIN", "")

    # Go: $GOBIN, $GOPATH/bin, ~/go/bin
    if gobin:
        dirs.append(gobin)
    if gopath:
        for part in gopath.split(os.pathsep):
            if part:
                dirs.append(os.path.join(part, "bin"))
    dirs.append(os.path.join(home, "go", "bin"))

    # Каталог go/bin пользователя root — частый случай установки от sudo/root.
    dirs.append("/root/go/bin")

    # snap
    dirs.append("/snap/bin")
    dirs.append("/var/lib/snapd/snap/bin")

    # Ручная установка / системные каталоги
    dirs += [
        "/usr/local/bin",
        "/usr/local/go/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        os.path.join(home, ".local", "bin"),
    ]

    # Уникализируем, сохраняя порядок, и оставляем только существующие каталоги.
    seen, out = set(), []
    for d in dirs:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append(d)
    return out


def which(name):
    """Найти бинарник `name` в PATH ИЛИ в типовых каталогах установки.

    Возвращает абсолютный путь либо None. Безопасна к ошибкам ФС.
    """
    # 1) Штатный поиск по PATH.
    path = shutil.which(name)
    if path:
        return path
    # 2) Расширенный поиск по типовым каталогам.
    for d in _extra_dirs():
        cand = os.path.join(d, name)
        try:
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        except OSError:
            continue
    return None


def augment_path():
    """Добавить типовые каталоги установки в PATH процесса (идемпотентно).

    Вызывается один раз при старте сканера, чтобы дочерние процессы
    (subprocess) тоже видели dalfox/snap-утилиты. Возвращает список реально
    добавленных каталогов (для логирования).
    """
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep) if current else []
    present = set(parts)
    added = []
    for d in _extra_dirs():
        if d not in present:
            parts.append(d)
            present.add(d)
            added.append(d)
    os.environ["PATH"] = os.pathsep.join(parts)
    return added


if __name__ == "__main__":
    print("Доп. каталоги поиска утилит:")
    for d in _extra_dirs():
        print("  ", d)
    for t in ("dalfox", "nikto", "wpscan", "nmap", "curl"):
        print(f"  which({t}) = {which(t)}")
