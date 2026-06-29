#!/usr/bin/env bash
# =============================================================================
#  NetInv — автоматический инсталлятор для Debian-совместимых систем
#  (Kali Linux, Ubuntu, Debian, Parrot и т.п.)
#
#  Что делает:
#    1. Проверяет, что система Debian-совместима (есть apt-get).
#    2. Устанавливает системные пакеты: nmap, whatweb, curl, dnsutils (dig),
#       dnsmap, dnsenum, dnsrecon (разведка поддоменов),
#       nikto, wpscan, dalfox (базовая проверка web-уязвимостей, требование 5),
#       python3, python3-venv, python3-pip (через apt-get).
#    3. Создаёт изолированное Python-окружение (.venv) и ставит зависимости.
#    4. Инициализирует базу данных SQLite.
#    5. Делает запускаемые скрипты исполняемыми.
#
#  Запуск:   sudo ./install.sh           (рекомендуется для установки пакетов)
#            ./install.sh                (если пакеты уже стоят / без sudo)
#
#  После установки запускайте всё одной командой:  ./netinv
# =============================================================================
set -euo pipefail

# --- цвета вывода ---
c_ok=$'\033[0;32m'; c_warn=$'\033[0;33m'; c_err=$'\033[0;31m'; c_inf=$'\033[0;36m'; c_off=$'\033[0m'
log()  { echo "${c_inf}[*]${c_off} $*"; }
ok()   { echo "${c_ok}[+]${c_off} $*"; }
warn() { echo "${c_warn}[!]${c_off} $*"; }
die()  { echo "${c_err}[x]${c_off} $*" >&2; exit 1; }

# --- каталог проекта (туда, где лежит install.sh) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- обёртка sudo: используем только если не root и sudo доступен ---
SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  fi
fi

# --- 1. проверка Debian-совместимости ---
if ! command -v apt-get >/dev/null 2>&1; then
  die "apt-get не найден. Инсталлятор рассчитан на Debian-совместимые системы (Kali/Ubuntu/Debian)."
fi
log "Обнаружена Debian-совместимая система."

# --- 2. системные пакеты ---
# Обязательные пакеты — без них сканер не работает.
PKGS=(nmap whatweb curl dnsutils python3 python3-venv python3-pip)
# Опциональные пакеты — утилиты поиска поддоменов (в Kali входят в
# метапакеты; на чистом Debian могут отсутствовать). Сканер деградирует
# корректно, если какой-то из них не установлен, поэтому их установка
# не обязательна и не прерывает установку при ошибке.
# Сюда же входят утилиты базовой проверки web-уязвимостей (требование 5):
# nikto, wpscan. На Kali они доступны в репозиториях; на чистом
# Debian часть из них может отсутствовать — сканер работает и без них
# (уязвимости проверяются доступными средствами: curl, nmap http-скрипты).
# ВНИМАНИЕ: dalfox в apt-репозиториях Kali/Debian по умолчанию ОТСУТСТВУЕТ,
# поэтому он НЕ входит в OPT_PKGS — его ставит отдельная секция ниже
# (через go install либо snap), см. «# --- 2б. установка dalfox».
OPT_PKGS=(dnsmap dnsenum dnsrecon nikto wpscan)
MISSING=()
for p in "${PKGS[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    MISSING+=("$p")
  fi
done
OPT_MISSING=()
for p in "${OPT_PKGS[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    OPT_MISSING+=("$p")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  log "Будут установлены пакеты: ${MISSING[*]}"
  if [[ -z "$SUDO" && "${EUID:-$(id -u)}" -ne 0 ]]; then
    warn "Нет root и sudo — пропускаю установку пакетов. Установите вручную:"
    warn "    apt-get install -y ${MISSING[*]}"
  else
    $SUDO apt-get update -y
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "${MISSING[@]}"
    ok "Системные пакеты установлены."
  fi
else
  ok "Все обязательные системные пакеты уже установлены."
fi

# Опциональные пакеты разведки поддоменов — ставим по отдельности,
# чтобы отсутствие пакета в репозитории не прерывало установку.
if [[ ${#OPT_MISSING[@]} -gt 0 ]]; then
  if [[ -z "$SUDO" && "${EUID:-$(id -u)}" -ne 0 ]]; then
    warn "Нет root — пропускаю опциональные пакеты разведки: ${OPT_MISSING[*]}"
  else
    log "Устанавливаю опциональные пакеты разведки поддоменов: ${OPT_MISSING[*]}"
    for op in "${OPT_MISSING[@]}"; do
      if DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "$op" 2>/dev/null; then
        ok "Установлен $op."
      else
        warn "Не удалось установить $op — поиск поддоменов этой утилитой будет пропущен."
      fi
    done
  fi
fi

# --- 2б. установка dalfox (требование 1 v1.5.0) ----------------------------
# dalfox — лёгкая проверка XSS. В apt-репозиториях Kali/Debian по умолчанию
# его НЕТ, поэтому ставим одним из двух способов:
#   1) ПРИОРИТЕТ — `go install github.com/hahwul/dalfox/v2@latest`
#      (при отсутствии Go ставим пакет golang-go через apt);
#   2) ФОЛБЭК   — `snap install dalfox` (при отсутствии snapd ставим snapd).
# go install кладёт бинарник в $GOPATH/bin (обычно ~/go/bin или /root/go/bin),
# поэтому в конце делаем симлинк в /usr/local/bin/dalfox — он гарантированно
# в PATH у web/cron-процессов NetInv (требование 2). Установка может
# запрашивать root — это ДОПУСТИМО. Любые сбои не прерывают установку:
# сканер корректно деградирует без dalfox.
install_dalfox() {
  # Уже установлен и виден в PATH или в типовых каталогах? — выходим.
  for cand in dalfox "$HOME/go/bin/dalfox" /root/go/bin/dalfox /snap/bin/dalfox /usr/local/bin/dalfox; do
    if command -v "$cand" >/dev/null 2>&1 || [[ -x "$cand" ]]; then
      ok "dalfox уже установлен ($cand)."
      return 0
    fi
  done

  log "Устанавливаю dalfox (лёгкая проверка XSS) ..."

  # --- способ 1: go install -------------------------------------------------
  if ! command -v go >/dev/null 2>&1; then
    log "Go не найден — пробую установить пакет golang-go (нужен root) ..."
    if [[ -n "$SUDO" || "${EUID:-$(id -u)}" -eq 0 ]]; then
      DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y golang-go 2>/dev/null \
        || warn "Не удалось поставить golang-go через apt — попробую snap."
    else
      warn "Нет root/sudo — пакет golang-go не установить; попробую snap."
    fi
  fi

  if command -v go >/dev/null 2>&1; then
    # GOBIN определяем явно, чтобы знать, куда лёг бинарник, и не зависеть от
    # настроек окружения. Под sudo HOME может быть /root.
    local gobin
    gobin="$(go env GOBIN 2>/dev/null || true)"
    if [[ -z "$gobin" ]]; then
      gobin="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
    fi
    log "go install github.com/hahwul/dalfox/v2@latest (каталог: $gobin) ..."
    if GOBIN="$gobin" go install github.com/hahwul/dalfox/v2@latest 2>/dev/null; then
      if [[ -x "$gobin/dalfox" ]]; then
        # Симлинк в /usr/local/bin, чтобы dalfox был в PATH у любых процессов.
        if [[ -n "$SUDO" || "${EUID:-$(id -u)}" -eq 0 ]]; then
          $SUDO ln -sf "$gobin/dalfox" /usr/local/bin/dalfox 2>/dev/null \
            && ok "dalfox установлен через go; симлинк: /usr/local/bin/dalfox -> $gobin/dalfox" \
            || ok "dalfox установлен через go: $gobin/dalfox (симлинк не создан — добавьте $gobin в PATH)"
        else
          ok "dalfox установлен через go: $gobin/dalfox"
          warn "Нет root — симлинк в /usr/local/bin не создан. Добавьте в PATH: export PATH=\"$gobin:\$PATH\""
        fi
        return 0
      fi
    fi
    warn "go install dalfox не удался — пробую snap."
  fi

  # --- способ 2: snap install (фолбэк) -------------------------------------
  if ! command -v snap >/dev/null 2>&1; then
    log "snap не найден — пробую установить snapd (нужен root) ..."
    if [[ -n "$SUDO" || "${EUID:-$(id -u)}" -eq 0 ]]; then
      DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y snapd 2>/dev/null \
        || warn "Не удалось поставить snapd через apt."
    else
      warn "Нет root/sudo — snapd не установить."
    fi
  fi

  if command -v snap >/dev/null 2>&1; then
    log "snap install dalfox ..."
    if [[ -n "$SUDO" || "${EUID:-$(id -u)}" -eq 0 ]]; then
      if $SUDO snap install dalfox 2>/dev/null; then
        # snap-бинарники лежат в /snap/bin; симлинк для надёжности.
        [[ -x /snap/bin/dalfox ]] && $SUDO ln -sf /snap/bin/dalfox /usr/local/bin/dalfox 2>/dev/null || true
        ok "dalfox установлен через snap."
        return 0
      fi
    fi
    warn "snap install dalfox не удался."
  fi

  # --- не получилось ни одним способом -------------------------------------
  warn "Не удалось установить dalfox автоматически — лёгкая проверка XSS будет пропущена."
  warn "    Установите вручную:  go install github.com/hahwul/dalfox/v2@latest"
  warn "    либо:                sudo snap install dalfox"
  return 1
}
install_dalfox || true

# --- проверка ключевых инструментов ---
for t in nmap curl python3; do
  command -v "$t" >/dev/null 2>&1 || die "Не найден '$t' даже после установки. Установите вручную."
done
command -v whatweb >/dev/null 2>&1 || warn "whatweb не найден — web-фингерпринт будет ограничен (curl-fallback)."
command -v dig >/dev/null 2>&1 || warn "dig не найден — поле «Доменное имя» заполняется только из nmap (установите пакет dnsutils)."
# Утилиты разведки поддоменов — опциональны; сканер работает и без них.
for dtool in dnsmap dnsenum dnsrecon; do
  command -v "$dtool" >/dev/null 2>&1 || warn "$dtool не найден — поиск поддоменов этой утилитой будет пропущен (установите пакет $dtool)."
done
# Утилиты базовой проверки web-уязвимостей (требование 5) — тоже опциональны.
for wtool in nikto wpscan; do
  command -v "$wtool" >/dev/null 2>&1 || warn "$wtool не найден — углублённая проверка web-уязвимостей этой утилитой будет пропущена (базовые проверки curl/nmap работают всё равно)."
done
# dalfox ищем шире (в т.ч. в ~/go/bin, /snap/bin, /usr/local/bin), т.к. он
# ставится не через apt и может быть не в PATH этой оболочки.
if ! command -v dalfox >/dev/null 2>&1 \
   && [[ ! -x "$HOME/go/bin/dalfox" ]] && [[ ! -x /root/go/bin/dalfox ]] \
   && [[ ! -x /snap/bin/dalfox ]] && [[ ! -x /usr/local/bin/dalfox ]]; then
  warn "dalfox не найден — лёгкая проверка XSS будет пропущена (см. секцию установки dalfox выше)."
fi

# --- 3. python venv + зависимости ---
if [[ ! -d ".venv" ]]; then
  log "Создаю виртуальное окружение .venv ..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
log "Обновляю pip и ставлю зависимости ..."

# Устойчивые к медленной сети параметры pip: большой таймаут + ретраи
# (лечит ReadTimeoutError при обращении к files.pythonhosted.org).
PIP_NET_OPTS=(--timeout 120 --retries 10)

# Без --upgrade pip: обновление pip необязательно и чаще всего именно оно
# падает по таймауту; пробуем, но не падаем, если не вышло.
if ! python -m pip install "${PIP_NET_OPTS[@]}" --quiet --upgrade pip; then
  warn "Не удалось обновить pip (сеть?) — продолжаю с текущим pip."
fi

# Установка зависимостей с повторной попыткой при сбое сети.
if ! python -m pip install "${PIP_NET_OPTS[@]}" --quiet -r requirements.txt; then
  warn "Первая попытка установки зависимостей не удалась, повторяю ..."
  python -m pip install "${PIP_NET_OPTS[@]}" -r requirements.txt \
    || die "Не удалось установить Python-зависимости. Проверьте доступ в Интернет и повторите ./install.sh"
fi
ok "Python-зависимости установлены."

# --- 4. инициализация БД ---
log "Инициализирую базу данных ..."
mkdir -p data
python scanner/db.py
ok "База данных готова."

# --- 4б. КРИТИЧНО: права на каталог data/ и файл БД -----------------------
# Если install.sh запущен под sudo, то data/ и data.db создаются от root.
# Тогда web-приложение, запущенное от обычного пользователя, не сможет
# писать в SQLite (sqlite3.OperationalError: attempt to write a readonly
# database). SQLite требует прав записи И на файл БД, И на каталог
# (из-за WAL/-journal). Возвращаем владение исходному пользователю.
if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  TARGET_USER="$SUDO_USER"
  TARGET_GROUP="$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")"
  log "Возвращаю владение data/ пользователю ${TARGET_USER}:${TARGET_GROUP} ..."
  chown -R "${TARGET_USER}:${TARGET_GROUP}" data 2>/dev/null || true
  # На всякий случай владение всего проекта (.venv и пр.) тоже.
  chown -R "${TARGET_USER}:${TARGET_GROUP}" "$SCRIPT_DIR" 2>/dev/null || true
  ok "Права на каталог data/ исправлены."
fi
# Гарантируем права записи на каталог и файл БД (страховка).
chmod u+rwx data 2>/dev/null || true
[[ -f data/data.db ]] && chmod u+rw data/data.db 2>/dev/null || true

# --- 4в. каталог логов /opt/netinv/logs (требование 5 v1.4.0) --------------
# Подробные логи сканирований по умолчанию пишутся в /opt/netinv/logs
# (имя файла netinv_YYMMDD_TIME.log). Каталог /opt принадлежит root,
# поэтому при наличии прав создаём его заранее и отдаём владение
# исходному пользователю. Если прав нет — это НЕ ошибка: модуль
# logsetup.py аккуратно деградирует на <корень проекта>/logs, а при
# недоступности и его — на /tmp/netinv_logs. Переопределить путь можно
# переменной окружения NETINV_LOG_DIR.
LOG_DIR="/opt/netinv/logs"
if [[ -n "$SUDO" || "${EUID:-$(id -u)}" -eq 0 ]]; then
  if $SUDO mkdir -p "$LOG_DIR" 2>/dev/null; then
    # отдаём владение исходному пользователю, чтобы web/cron от обычного
    # пользователя могли писать логи.
    if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
      LOG_OWNER="${SUDO_USER}:$(id -gn "${SUDO_USER}" 2>/dev/null || echo "${SUDO_USER}")"
      chown -R "$LOG_OWNER" "$LOG_DIR" 2>/dev/null || true
    fi
    $SUDO chmod 0775 "$LOG_DIR" 2>/dev/null || true
    ok "Каталог логов готов: $LOG_DIR"
  else
    warn "Не удалось создать $LOG_DIR — логи будут писаться в <корень проекта>/logs (фолбэк)."
  fi
else
  warn "Нет root/sudo — каталог $LOG_DIR не создан; логи пойдут в <корень проекта>/logs (фолбэк)."
  warn "    Чтобы использовать путь по умолчанию: sudo mkdir -p $LOG_DIR && sudo chown -R \$USER $LOG_DIR"
fi
# Локальный фолбэк-каталог логов внутри проекта создаём всегда — на случай,
# если /opt/netinv/logs недоступен во время запуска сканирования.
mkdir -p "$SCRIPT_DIR/logs" 2>/dev/null || true

# --- 5. системная группа cpt -----------------------------------------------
# Доступ к NetInv разрешён только группе cpt (Continuous Penetration
# Test). На уровне ОС создаём реальную группу cpt (для разграничения
# прав на файлы проекта), а внутри приложения принадлежность к cpt
# эмулируется флагом in_cpt в таблице users.
if command -v groupadd >/dev/null 2>&1; then
  if [[ -n "$SUDO" || "${EUID:-$(id -u)}" -eq 0 ]]; then
    if ! getent group cpt >/dev/null 2>&1; then
      log "Создаю системную группу cpt ..."
    fi
    $SUDO groupadd -f cpt 2>/dev/null || true
    ok "Группа cpt готова."
    # Привязываем исходного пользователя к группе cpt (удобство).
    if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
      usermod -aG cpt "${SUDO_USER}" 2>/dev/null \
        && ok "Пользователь ${SUDO_USER} добавлен в группу cpt." || true
    fi
  else
    warn "Нет root/sudo — создание группы cpt пропущено. Создайте вручную:"
    warn "    sudo groupadd -f cpt"
  fi
else
  warn "groupadd не найден — пропускаю создание группы cpt."
fi

# --- 6. интерактивное создание пользователей NetInv -----------------------
# Пользователи хранятся в таблице users (хеш пароля PBKDF2). Без хотя бы
# одного пользователя вход в web-приложение невозможен. Интерактивный
# режим работает только при наличии TTY (stdin) и без флага NETINV_NONINTERACTIVE.
EXISTING_USERS="$(python -c 'import sys; sys.path.insert(0, "scanner"); import db; db.init_db(); print(db.count_users())' 2>/dev/null || echo 0)"
if [[ "${NETINV_NONINTERACTIVE:-0}" == "1" ]]; then
  log "NETINV_NONINTERACTIVE=1 — пропускаю создание пользователей."
elif [[ ! -t 0 ]]; then
  warn "Нет интерактивного терминала — пропускаю создание пользователей."
  if [[ "$EXISTING_USERS" == "0" ]]; then
    warn "В БД нет ни одного пользователя. Создайте его позже:  ./netinv adduser"
  fi
else
  if [[ "$EXISTING_USERS" != "0" ]]; then
    log "В БД уже есть пользователи (${EXISTING_USERS} шт.)."
    printf "%b" "${c_inf}[*]${c_off} Добавить ещё пользователей NetInv? [y/N]: "
    read -r ans || ans=""
  else
    log "В БД нет пользователей — создадим хотя бы одного (иначе вход невозможен)."
    ans="y"
  fi
  if [[ "$ans" =~ ^([yY]|[дД])$ ]]; then
    # Модуль сам хеширует пароль (werkzeug PBKDF2) и пишет в таблицу users с in_cpt=1.
    python scanner/manage_users.py add --batch || warn "Создание пользователей прервано."
  fi
fi

# --- исправление владения data/ после возможной записи от root ---
if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  chown -R "${SUDO_USER}:$(id -gn "${SUDO_USER}" 2>/dev/null || echo "${SUDO_USER}")" data 2>/dev/null || true
fi

# --- 7. исполняемые скрипты ---
chmod +x netinv run.sh install.sh update.sh 2>/dev/null || true
chmod +x scanner/scanner.py scanner/manage_users.py run_cron.py webapp/app.py 2>/dev/null || true

echo
ok "Установка завершена."
echo
echo "  Запуск всей системы одной командой:"
echo "      ${c_inf}./netinv${c_off}                      # web-приложение на http://127.0.0.1:5000"
echo "      ${c_inf}./netinv --host 0.0.0.0 --port 8080${c_off}   # доступ в LAN (осторожно!)"
echo
echo "  Разовый прогон всех объектов из CLI (для cron):"
echo "      ${c_inf}./netinv scan --main${c_off}           # ОСНОВНОЙ скан (фиксированный пресет)"
echo "      ${c_inf}./netinv scan${c_off}                  # РАСШИРЕННЫЙ, обход SYN-защиты (по умолч.)"
echo "      ${c_inf}./netinv scan --syn-mode direct${c_off}  # без обхода (нужен root для -sS)"
echo
echo "  Управление пользователями (вход разрешён только группе cpt):"
echo "      ${c_inf}./netinv adduser${c_off}               # создать/обновить пользователя"
echo
