#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reset_cli.py — сброс данных NetInv (v1.6.0, треб. 6).

Два режима (вызываются из launcher `./netinv`):

  * dbreset  (netinv -dbreset)
        Обнуляет БД и всю ИСТОРИЮ сканирований (запуски, узлы, порты,
        web-ресурсы, уязвимости, ошибки/модули сканирования, состояния узлов,
        происхождение IP, найденные поддомены).
        СОХРАНЯЮТСЯ: пользователи, заведённые объекты сканирования и их домены,
        описания/атрибуты IP, а также файлы каталога ./logs.
        Требует подтверждения (Да/Нет).

  * fullreset (netinv -fullreset)
        Полный откат к «чистой» версии — как сразу после установки. УДАЛЯЕТ
        файл БД целиком (все пользователи, объекты, история) и пересоздаёт
        пустую схему. Файлы ./logs НЕ трогаются (журналы — на диске).
        Требует АВТОРИЗАЦИИ внутреннего пользователя проекта (in_cpt=1) и
        отдельного подтверждения.
"""
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402

try:
    from werkzeug.security import check_password_hash
except Exception:  # noqa: BLE001
    check_password_hash = None


def _confirm(prompt):
    """Запросить подтверждение Да/Нет (по умолчанию — Нет)."""
    try:
        ans = input(f"{prompt} [да/Нет]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("да", "y", "yes", "д")


def _authorize():
    """Авторизация внутреннего пользователя проекта (in_cpt=1) для fullreset.

    Возвращает True при успешной проверке логина/пароля существующего
    пользователя с доступом. Три попытки.
    """
    db.init_db()
    if db.count_users() == 0:
        # Пользователей нет — авторизовывать некого; система и так «чистая»
        # по учёткам. Разрешаем откат (полезно на свежей установке).
        print("[!] В базе нет пользователей — авторизация пропущена.")
        return True
    if check_password_hash is None:
        print("[x] Не найден werkzeug — проверка пароля невозможна.",
              file=sys.stderr)
        return False
    print("Для полного отката требуется авторизация пользователя проекта "
          "(с доступом cpt).")
    for attempt in range(3):
        try:
            username = input("Пользователь: ").strip()
            password = getpass.getpass("Пароль: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        user = db.get_user(username)
        if user and user.get("in_cpt") and check_password_hash(
                user["pw_hash"], password):
            print(f"[+] Авторизация успешна: {username}.")
            return True
        print(f"[!] Неверные учётные данные или нет доступа "
              f"(осталось попыток: {2 - attempt}).")
    return False


def do_dbreset():
    """netinv -dbreset — обнулить историю, сохранить учётки/объекты/логи."""
    print("=" * 70)
    print("ОБНУЛЕНИЕ БАЗЫ ДАННЫХ (история сканирований)")
    print("Будут удалены: все запуски, узлы, порты, web-ресурсы, уязвимости,")
    print("ошибки и модули сканирования, состояния узлов, происхождение IP,")
    print("найденные поддомены.")
    print("Сохранятся: пользователи, объекты сканирования и их домены,")
    print("описания/атрибуты IP, файлы каталога ./logs.")
    print("=" * 70)
    if not _confirm("Обнулить историю сканирований?"):
        print("[*] Отменено. Изменений нет.")
        return 1
    db.init_db()
    n = db.reset_database()
    print(f"[+] Готово. Удалено запусков: {n}. "
          f"Пользователи и объекты сохранены.")
    return 0


def do_fullreset():
    """netinv -fullreset — полный откат к «чистой» версии (после авторизации)."""
    print("=" * 70)
    print("ПОЛНЫЙ ОТКАТ NetInv к «ЧИСТОЙ» ВЕРСИИ (как после установки)")
    print("Будет удалена ВСЯ база данных: пользователи, объекты сканирования,")
    print("домены, описания/атрибуты IP и вся история. Файлы ./logs остаются.")
    print("Действие НЕОБРАТИМО.")
    print("=" * 70)
    if not _authorize():
        print("[x] Авторизация не пройдена. Откат отменён.")
        return 2
    if not _confirm("ПОДТВЕРДИТЕ полный откат (все данные будут удалены)?"):
        print("[*] Отменено. Изменений нет.")
        return 1
    # Удаляем файл БД целиком и пересоздаём пустую схему.
    removed = []
    for suffix in ("", "-wal", "-shm"):
        path = db.DB_PATH + suffix
        try:
            if os.path.exists(path):
                os.remove(path)
                removed.append(os.path.basename(path))
        except OSError as e:
            print(f"[!] Не удалось удалить {path}: {e}")
    db.init_db()  # пересоздаём пустую схему
    print(f"[+] Готово. База сброшена к чистому состоянию "
          f"(удалены: {', '.join(removed) or 'нет файлов'}).")
    print("[*] Создайте пользователя: ./netinv adduser")
    return 0


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    mode = argv[0] if argv else ""
    if mode == "dbreset":
        return do_dbreset()
    if mode == "fullreset":
        return do_fullreset()
    print("Использование: reset_cli.py {dbreset|fullreset}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
