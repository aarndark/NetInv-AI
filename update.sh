#!/usr/bin/env bash
# =============================================================================
#  update.sh — обновление NetInv до актуальной версии из ЛОКАЛЬНОГО источника.
#
#  Рассчитан на оффлайн/изолированные среды (Continuous Pentest без интернета):
#  новая версия поставляется как локальный архив netinv.tar.gz либо как
#  распакованный каталог рядом с установкой.
#
#  Что делает:
#    1. Определяет источник новой версии (аргумент или автопоиск netinv.tar.gz).
#    2. Распаковывает/копирует новую версию во временный каталог и проверяет её.
#    3. Делает РЕЗЕРВНУЮ КОПИЮ текущего кода и базы data/data.db (timestamped).
#    4. Обновляет файлы кода, СОХРАНЯЯ data/data.db без изменений.
#    5. Обновляет зависимости в существующем .venv (requirements.txt).
#    6. Применяет миграции схемы БД (db.init_db() — без потери данных).
#    7. Сообщает старую и новую версии (файл VERSION).
#
#  Использование:
#    ./netinv update                     Автопоиск netinv.tar.gz рядом с проектом
#    ./netinv update <архив.tar.gz>       Обновление из указанного архива
#    ./netinv update <каталог>            Обновление из распакованного каталога
#    ./update.sh [...]                    То же напрямую
#
#  Опции:
#    --no-deps        Не переустанавливать зависимости в .venv
#    --no-backup      Не делать резервную копию (НЕ рекомендуется)
#    -y, --yes        Не запрашивать подтверждение
#    -h, --help       Справка
#
#  ВНИМАНИЕ: data/data.db (история сканов, пользователи, описания IP) НИКОГДА
#  не перезаписывается — переносится из текущей установки как есть, после чего
#  применяются только миграции схемы.
# =============================================================================
set -euo pipefail

# --- каталог установки (туда, где лежит этот скрипт) ---
DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEST_DIR"

# --- цветной вывод ---
c_inf=$'\033[0;36m'; c_ok=$'\033[0;32m'; c_warn=$'\033[0;33m'; c_err=$'\033[0;31m'; c_off=$'\033[0m'
log()  { echo "${c_inf}[*]${c_off} $*"; }
ok()   { echo "${c_ok}[OK]${c_off} $*"; }
warn() { echo "${c_warn}[!]${c_off} $*" >&2; }
die()  { echo "${c_err}[ОШИБКА]${c_off} $*" >&2; exit 1; }

# --- разбор аргументов ---
SRC=""
DO_DEPS=1
DO_BACKUP=1
ASSUME_YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-deps)   DO_DEPS=0; shift;;
    --no-backup) DO_BACKUP=0; shift;;
    -y|--yes)    ASSUME_YES=1; shift;;
    -h|--help)
      sed -n '2,46p' "$0" | sed 's/^#\s\?//'
      exit 0;;
    -*)
      die "Неизвестная опция: $1 (см. ./update.sh --help)";;
    *)
      [[ -z "$SRC" ]] && SRC="$1" || die "Лишний аргумент: $1"
      shift;;
  esac
done

read_version() {
  # $1 — каталог; печатает версию или 'неизвестно'
  if [[ -f "$1/VERSION" ]]; then
    head -n1 "$1/VERSION" | tr -d '[:space:]'
  else
    echo "неизвестно"
  fi
}

# --- 1. определяем источник новой версии ---
if [[ -z "$SRC" ]]; then
  # Автопоиск архива рядом с установкой и на уровень выше.
  for cand in "$DEST_DIR/netinv.tar.gz" "$DEST_DIR/../netinv.tar.gz" "./netinv.tar.gz"; do
    if [[ -f "$cand" ]]; then SRC="$cand"; break; fi
  done
  [[ -z "$SRC" ]] && die "Источник не указан и netinv.tar.gz не найден. Укажите архив или каталог: ./netinv update <путь>"
  log "Автоопределён источник: $SRC"
fi
[[ -e "$SRC" ]] || die "Источник не найден: $SRC"

# --- 2. готовим распакованную новую версию во временном каталоге ---
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
NEW_SRC=""   # каталог с новой версией (где лежат scanner/, webapp/, install.sh ...)

if [[ -d "$SRC" ]]; then
  log "Источник — каталог, копирую во временную папку ..."
  cp -a "$SRC/." "$TMP_DIR/extracted/" 2>/dev/null || { mkdir -p "$TMP_DIR/extracted"; cp -a "$SRC/." "$TMP_DIR/extracted/"; }
  NEW_SRC="$TMP_DIR/extracted"
elif [[ -f "$SRC" ]]; then
  case "$SRC" in
    *.tar.gz|*.tgz) log "Распаковываю архив $SRC ..."; mkdir -p "$TMP_DIR/extracted"; tar xzf "$SRC" -C "$TMP_DIR/extracted";;
    *) die "Неподдерживаемый формат источника: $SRC (ожидается .tar.gz/.tgz или каталог)";;
  esac
  # Архив может содержать вложенный каталог netinv/ — находим корень проекта.
  if [[ -f "$TMP_DIR/extracted/install.sh" ]]; then
    NEW_SRC="$TMP_DIR/extracted"
  elif [[ -f "$TMP_DIR/extracted/netinv/install.sh" ]]; then
    NEW_SRC="$TMP_DIR/extracted/netinv"
  else
    # ищем глубже единственный каталог с install.sh
    found="$(find "$TMP_DIR/extracted" -maxdepth 3 -name install.sh -printf '%h\n' 2>/dev/null | head -n1 || true)"
    [[ -n "$found" ]] && NEW_SRC="$found"
  fi
fi
[[ -n "$NEW_SRC" && -d "$NEW_SRC" ]] || die "Не удалось найти корень проекта в источнике (нет install.sh)."

# --- проверка целостности новой версии ---
for required in scanner/db.py scanner/scanner.py webapp/app.py requirements.txt; do
  [[ -f "$NEW_SRC/$required" ]] || die "Источник повреждён или это не NetInv: нет $required"
done

OLD_VER="$(read_version "$DEST_DIR")"
NEW_VER="$(read_version "$NEW_SRC")"
log "Текущая версия: ${OLD_VER}  →  новая версия: ${NEW_VER}"
if [[ "$OLD_VER" == "$NEW_VER" && "$OLD_VER" != "неизвестно" ]]; then
  warn "Версии совпадают (${OLD_VER}). Обновление переустановит те же файлы кода."
fi

# --- подтверждение ---
if [[ "$ASSUME_YES" -ne 1 ]]; then
  printf "%sПродолжить обновление установки в %s? [y/N] %s" "$c_warn" "$DEST_DIR" "$c_off"
  read -r ans
  case "$ans" in y|Y|yes|Yes|да|Да) ;; *) die "Отменено пользователем.";; esac
fi

# --- 3. резервная копия ---
if [[ "$DO_BACKUP" -eq 1 ]]; then
  TS="$(date +%Y%m%d_%H%M%S)"
  BACKUP_DIR="$DEST_DIR/backups/$TS"
  mkdir -p "$BACKUP_DIR"
  log "Создаю резервную копию в backups/$TS ..."
  # БД (если есть)
  if [[ -f "$DEST_DIR/data/data.db" ]]; then
    mkdir -p "$BACKUP_DIR/data"
    cp -a "$DEST_DIR/data/data.db"* "$BACKUP_DIR/data/" 2>/dev/null || true
  fi
  # Снимок текущего кода (без .venv, backups и БД — их сохраняем отдельно)
  tar czf "$BACKUP_DIR/code_prev.tar.gz" \
    --exclude='./.venv' --exclude='./backups' --exclude='./data/data.db*' \
    -C "$DEST_DIR" . 2>/dev/null || warn "Снимок кода создан с предупреждениями."
  ok "Резервная копия готова: $BACKUP_DIR"
else
  warn "Резервная копия отключена (--no-backup)."
fi

# --- 4. обновление файлов кода (data/ и .venv и backups/ не трогаем) ---
log "Обновляю файлы проекта (data/data.db и .venv сохраняются) ..."
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete \
    --exclude='.venv/' \
    --exclude='backups/' \
    --exclude='data/data.db' \
    --exclude='data/data.db-*' \
    "$NEW_SRC"/ "$DEST_DIR"/
else
  # Fallback без rsync: копируем поверх (без удаления устаревших файлов).
  warn "rsync не найден — копирую поверх (устаревшие файлы не удаляются)."
  ( cd "$NEW_SRC" && \
    find . -type d ! -path './data/*' -exec mkdir -p "$DEST_DIR/{}" \; && \
    find . -type f ! -path './data/data.db*' -exec cp -a "{}" "$DEST_DIR/{}" \; )
fi
# гарантируем, что каталог data существует
mkdir -p "$DEST_DIR/data"
ok "Файлы кода обновлены."

# --- права на запуск ---
for f in netinv install.sh update.sh run.sh; do
  [[ -f "$DEST_DIR/$f" ]] && chmod +x "$DEST_DIR/$f" 2>/dev/null || true
done

# --- 5. зависимости ---
if [[ "$DO_DEPS" -eq 1 ]]; then
  if [[ -d "$DEST_DIR/.venv" ]]; then
    log "Обновляю зависимости в .venv (requirements.txt) ..."
    "$DEST_DIR/.venv/bin/pip" install --upgrade -r "$DEST_DIR/requirements.txt" \
      || warn "Не удалось обновить часть зависимостей — проверьте вывод выше."
    ok "Зависимости обновлены."
  else
    warn "Каталог .venv не найден — запустите ./install.sh для первичной установки."
  fi
else
  log "Пропуск обновления зависимостей (--no-deps)."
fi

# --- 6. миграции схемы БД (без потери данных) ---
if [[ -x "$DEST_DIR/.venv/bin/python" ]]; then
  log "Применяю миграции схемы базы данных (данные сохраняются) ..."
  ( cd "$DEST_DIR" && .venv/bin/python -c "import sys; sys.path.insert(0,'scanner'); import db; db.init_db(); print('schema_ok')" ) \
    && ok "Схема БД актуальна." \
    || warn "Не удалось применить миграции автоматически — выполните './netinv install' или проверьте data/data.db."
else
  warn "Python из .venv недоступен — миграции БД не применены (запустите ./install.sh)."
fi

# --- 7. итог ---
echo
ok "Обновление завершено: ${OLD_VER} → $(read_version "$DEST_DIR")"
[[ "$DO_BACKUP" -eq 1 ]] && log "Откат: восстановите код из backups/<метка>/code_prev.tar.gz и БД из backups/<метка>/data/."
log "Запуск web-приложения:  ./netinv"
log "Разовый прогон сканов:  ./netinv scan --main"
