#!/usr/bin/env bash
# run.sh — алиас для запуска всей системы одной командой.
# Эквивалент: ./netinv web  (web-приложение на http://127.0.0.1:5000).
# Все аргументы передаются в netinv как есть.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/netinv" "$@"
