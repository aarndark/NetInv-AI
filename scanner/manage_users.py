#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manage_users.py — управление локальными пользователями NetInv.

Пользователи NetInv хранятся в таблице БД `users` (хеш пароля — werkzeug
PBKDF2). Принадлежность к группе cpt эмулируется флагом in_cpt: доступ к
web-приложению разрешён только пользователям с in_cpt=1.

Использование:
    python manage_users.py add [USERNAME]      — создать/обновить пользователя
                                                 (пароль запрашивается скрыто);
                                                 без USERNAME — спросит имя.
    python manage_users.py add --batch         — интерактивный цикл: добавлять
                                                 пользователей, пока не пусто.
    python manage_users.py list                — список пользователей.
    python manage_users.py del USERNAME        — удалить пользователя.

Вызывается из install.sh (интерактивное создание при установке) и из
launcher `./netinv adduser`.
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402

try:
    from werkzeug.security import generate_password_hash
except Exception:  # noqa: BLE001
    generate_password_hash = None


def _hash_password(password):
    if generate_password_hash is None:
        print("[x] Не найден werkzeug (pip install -r requirements.txt). "
              "Хеширование пароля невозможно.", file=sys.stderr)
        sys.exit(2)
    # PBKDF2-SHA256 — безопасный дефолт werkzeug.
    return generate_password_hash(password, method="pbkdf2:sha256")


def _prompt_password():
    """Скрытый ввод пароля с подтверждением."""
    while True:
        p1 = getpass.getpass("Пароль: ")
        if not p1:
            print("[!] Пустой пароль не допускается.")
            continue
        p2 = getpass.getpass("Повторите пароль: ")
        if p1 != p2:
            print("[!] Пароли не совпадают, попробуйте снова.")
            continue
        return p1


def add_user(username=None, in_cpt=True):
    """Создать/обновить одного пользователя (интерактивно запросит пароль)."""
    db.init_db()
    if not username:
        username = input("Имя пользователя: ").strip()
    username = (username or "").strip()
    if not username:
        print("[!] Пустое имя пользователя — пропуск.")
        return False
    password = _prompt_password()
    pw_hash = _hash_password(password)
    db.upsert_user(username, pw_hash, in_cpt=1 if in_cpt else 0)
    grp = "cpt" if in_cpt else "(без доступа)"
    print(f"[+] Пользователь '{username}' сохранён. Группа: {grp}.")
    return True


def add_batch():
    """Интерактивный цикл: добавлять пользователей, пока имя не пустое."""
    db.init_db()
    print("Создание пользователей NetInv (группа cpt). "
          "Пустое имя — завершить.")
    count = 0
    while True:
        username = input("\nИмя пользователя (Enter — закончить): ").strip()
        if not username:
            break
        if add_user(username, in_cpt=True):
            count += 1
    print(f"\n[*] Готово. Создано/обновлено пользователей: {count}.")
    if count == 0 and db.count_users() == 0:
        print("[!] Внимание: ни одного пользователя не создано. "
              "Вход в web-приложение будет невозможен. "
              "Добавьте пользователя позже: ./netinv adduser")


def list_users():
    db.init_db()
    users = db.list_users()
    if not users:
        print("[!] Пользователей нет.")
        return
    print(f"{'ID':<4} {'Пользователь':<24} {'Группа cpt':<10} Создан")
    for u in users:
        grp = "да" if u.get("in_cpt") else "нет"
        print(f"{u['id']:<4} {u['username']:<24} {grp:<10} {u.get('created_at', '')}")


def del_user(username):
    db.init_db()
    user = db.get_user(username)
    if not user:
        print(f"[!] Пользователь '{username}' не найден.")
        return
    with db.connect() as c:
        c.execute("DELETE FROM users WHERE username=?", (username,))
        c.commit()
    print(f"[+] Пользователь '{username}' удалён.")


def main():
    ap = argparse.ArgumentParser(description="Управление пользователями NetInv.")
    sub = ap.add_subparsers(dest="cmd")

    p_add = sub.add_parser("add", help="создать/обновить пользователя")
    p_add.add_argument("username", nargs="?", default=None)
    p_add.add_argument("--batch", action="store_true",
                       help="интерактивный цикл добавления нескольких пользователей")
    p_add.add_argument("--no-cpt", action="store_true",
                       help="создать пользователя БЕЗ доступа (in_cpt=0)")

    sub.add_parser("list", help="список пользователей")

    p_del = sub.add_parser("del", help="удалить пользователя")
    p_del.add_argument("username")

    args = ap.parse_args()

    if args.cmd == "add":
        if args.batch:
            add_batch()
        else:
            add_user(args.username, in_cpt=not args.no_cpt)
    elif args.cmd == "list":
        list_users()
    elif args.cmd == "del":
        del_user(args.username)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
