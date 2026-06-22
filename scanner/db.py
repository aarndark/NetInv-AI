#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db.py — слой работы с SQLite для системы инвентаризационного сканирования.

Хранит:
  - targets   : объекты сканирования (подсети/хосты), вводятся через web-приложение
  - scan_runs : запуски сканирования (один запуск = одно «прохождение» по target)
  - hosts     : обнаруженные сетевые узлы в рамках конкретного запуска
  - ports     : открытые порты + опубликованные сервисы для узла
  - webres    : выявленные web-ресурсы для узла
  - host_state: «склеенное» состояние узла по IP во времени (первое/предыдущее
                сканирование, рассчитанные отличия) — используется для табличного
                представления в требуемом формате.

Вся БД — один файл, ничего внешнего разворачивать не нужно (по выбору пользователя).
"""

import ipaddress
import os
import sqlite3
import threading
from contextlib import contextmanager


def ip_sort_key(ip):
    """Ключ для числовой сортировки IP по возрастанию (IPv4/IPv6).
    Некорректные значения уходят в конец."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def domain_sort_key(domain):
    """Ключ сортировки доменов «по уровням» (требование 1).

    Сначала домены 1-го уровня / TLD (.com, потом .org, потом .ru),
    затем 2-го уровня (coffee.ru, gravity.ru, zoon.ru), затем 3-го и ниже
    (alive.ya.ru, crimson.ya.ru, ...) и так далее. Внутри уровня —
    по меткам СПРАВА НАЛЕВО (TLD первым), чтобы однотипные
    домены группировались (напр. все *.ya.ru рядом).

    Дублируется в dns_recon.domain_sort_key — здесь оставлена
    самодостаточная копия, чтобы db.py не зависел от модуля разведки.
    """
    norm = (domain or "").strip().lower().rstrip(".")
    labels = [p for p in norm.split(".") if p]
    return (len(labels), tuple(reversed(labels)))

# Путь к файлу БД. Имя data.db — на случай переноса/публикации web-приложения.
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "data.db")

_LOCK = threading.Lock()

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Объекты сканирования: подсеть или отдельный хост (вводятся в web-приложении)
CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,              -- произвольное имя объекта
    cidr         TEXT NOT NULL,              -- 192.168.10.0/24 или 10.0.0.5
    description  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    enabled      INTEGER NOT NULL DEFAULT 1
);

-- Доменные имена, привязанные к объекту сканирования (дополнительно к CIDR).
-- Для доменов 2-го уровня (example.ru) выполняется разведка поддоменов
-- (dnsmap/dnsenum/dnsrecon). Для доменов 3+ уровня (sub.example.ru) —
-- просто резолв IP. Все полученные IP добавляются к сканированию.
CREATE TABLE IF NOT EXISTS target_domains (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    domain       TEXT NOT NULL,              -- example.ru или sub.example.ru
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, domain)
);

-- Запуски сканирования
CREATE TABLE IF NOT EXISTS scan_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    started_at   TEXT NOT NULL,              -- ISO datetime начала
    finished_at  TEXT,                       -- ISO datetime окончания
    status       TEXT NOT NULL DEFAULT 'running', -- running|done|error
    profile      TEXT,                       -- профиль таймингов nmap
    nmap_args    TEXT,                       -- фактическая командная строка
    log          TEXT,                       -- краткий лог / ошибки
    hosts_up     INTEGER DEFAULT 0,
    -- scan_class: класс сканирования.
    --   'main'     — ОСНОВНОЙ скан (фиксированный пресет: обход SYN-защиты -sT,
    --                профиль balanced, NSE, web, alive_no_ports). Статистика и
    --                отличия ведутся ОТДЕЛЬНО от расширенного.
    --   'advanced' — РАСШИРЕННЫЙ скан (все параметры выбираемы вручную).
    --                Итоги сохраняются и сравниваются отдельно от 'main'.
    scan_class   TEXT NOT NULL DEFAULT 'main',
    -- options_json: краткие опции расширенного запуска (для истории) — JSON со
    -- значениями: syn_mode, profile, ports, extra_nse, do_web, advanced_anp.
    options_json TEXT
);

-- Узлы, обнаруженные в конкретном запуске
CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    hostname     TEXT,                       -- доменное / reverse-DNS имя
    state        TEXT,                       -- up/down
    scanned_at   TEXT NOT NULL,
    -- alive_no_ports: узел "живой" (ответил на host discovery), но ни одного
    -- открытого TCP-порта не подтверждено. Кандидат на углублённую проверку
    -- (фантом SYN-cookie proxy / порт вне top-1000 / фильтрация и т.п.).
    alive_no_ports INTEGER NOT NULL DEFAULT 0,
    -- advanced_note: текстовое пояснение по итогам "alive_no_ports advanced
    -- check" (расширенная перепроверка -p-/--reason/-sU). NULL = не выполнялась.
    advanced_note  TEXT
);

-- Открытые порты + опубликованные сервисы для узла в конкретном запуске
CREATE TABLE IF NOT EXISTS ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port         INTEGER NOT NULL,
    proto        TEXT NOT NULL DEFAULT 'tcp',
    state        TEXT,                       -- open / open|filtered
    service      TEXT,                       -- ssh, http, ...
    product      TEXT,                       -- nginx, OpenSSH ...
    version      TEXT,
    extrainfo    TEXT,
    -- confidence: учёт SYN Flood/SYN Cookies. Полное TCP-рукопожатие (-sT)
    -- даёт "confirmed"; порт без подтверждения сервиса помечается "syncookie_suspect".
    confidence   TEXT DEFAULT 'confirmed'
);

-- Выявленные web-ресурсы для узла
CREATE TABLE IF NOT EXISTS webres (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    status_code  INTEGER,
    title        TEXT,
    server       TEXT,                       -- заголовок Server / технология
    tech         TEXT                        -- whatweb / доп. сигнатуры
);

-- Сводное состояние узла по IP во времени (для табличного отчёта).
-- Состояние ведётся ОТДЕЛЬНО по каждому классу сканирования (main/advanced):
-- ключ уникальности — (target_id, scan_class, ip).
CREATE TABLE IF NOT EXISTS host_state (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_class      TEXT NOT NULL DEFAULT 'main',
    ip              TEXT NOT NULL,
    first_seen      TEXT,                    -- дата первого ОБНАРУЖЕНИЯ узла
    last_run_id     INTEGER,                 -- последний (текущий) запуск
    prev_run_id     INTEGER,                 -- предыдущий запуск
    prev2_run_id    INTEGER,                 -- позапрошлый запуск
    last_scanned_at TEXT,
    prev_scanned_at TEXT,
    prev2_scanned_at TEXT,
    diff_prev       TEXT,                    -- отличия от предыдущего (JSON)
    diff_prev2      TEXT,                    -- отличия от позапрошлого (JSON)
    -- presence: pres|new|gone — присутствие IP относительно предыдущего
    -- запуска того же класса (для подсветки):
    --   new  — IP не было в прошлом сканировании ("Обнаружен новый IP");
    --   gone — IP был в прошлом, но отсутствует в текущем ("IP не найден");
    --   pres — обычное присутствие.
    presence        TEXT NOT NULL DEFAULT 'pres',
    UNIQUE(target_id, scan_class, ip)
);

-- Происхождение IP (как IP попал в скан): из диапазона CIDR, из домена
-- или из найденного поддомена. Привязано к (target_id, ip), не зависит от
-- запуска и класса — используется для обогащения итоговой таблицы
-- (колонка «Источник» и поле «Доменное имя»).
CREATE TABLE IF NOT EXISTS ip_origin (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    -- source: cidr | domain | subdomain
    source      TEXT NOT NULL DEFAULT 'cidr',
    -- domain: доменное/поддоменное имя, давшее этот IP (forward DNS), либо NULL
    domain      TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, ip)
);

-- Найденные поддомены по объекту (результат разведки доменов 2-го уровня).
-- Отдельная секция отчёта «Поддомены»: имя, IP, утилита, последний запуск.
CREATE TABLE IF NOT EXISTS discovered_subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    parent      TEXT NOT NULL,               -- родительский домен 2-го уровня
    subdomain   TEXT NOT NULL,               -- найденное FQDN-имя
    ip          TEXT,                        -- разрешённый IP (может быть NULL)
    tool        TEXT,                        -- dnsmap|dnsenum|dnsrecon|resolve
    last_run_id INTEGER,
    found_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, subdomain, ip)
);

-- Редактируемое "Описание" в привязке к IP-адресу (в рамках target).
-- Не зависит от класса сканирования и хранится между запусками.
CREATE TABLE IF NOT EXISTS ip_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, ip)
);

-- Требование 4: дополнительные атрибуты IP — «Администраторы» (свободный
-- текст) и «Контроль и защита» (набор флагов: CPT, SOC, сканер уязвимостей,
-- WAF, DDOS). Привязка к (target_id, ip), не зависит от класса сканирования и
-- хранится между запусками (как ip_notes).
CREATE TABLE IF NOT EXISTS ip_attributes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    admins          TEXT NOT NULL DEFAULT '',  -- «Администраторы» (текст)
    ctrl_cpt        INTEGER NOT NULL DEFAULT 0, -- Continuous Penetration Test
    ctrl_soc        INTEGER NOT NULL DEFAULT 0, -- SOC-мониторинг
    ctrl_vulnscan   INTEGER NOT NULL DEFAULT 0, -- сканер уязвимостей
    ctrl_waf        INTEGER NOT NULL DEFAULT 0, -- WAF
    ctrl_ddos       INTEGER NOT NULL DEFAULT 0, -- защита от DDOS
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, ip)
);

-- Требование 5: выявленные уязвимости/наблюдения web-ресурсов в рамках
-- конкретного запуска (привязка к hosts.id). Заполняется модулем webscan
-- (curl/whatweb/nikto/nmap-http/wpscan/dalfox) + классификатором vuln_rules.
CREATE TABLE IF NOT EXISTS vulns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    url             TEXT,                       -- web-ресурс, к которому относится
    -- severity: critical | warning | info — определяет подсветку.
    --   critical — требует максимально оперативного реагирования
    --              (админ-панели, тестовые разделы, RCE/SQLi/XSS, .git/.env/backup);
    --   warning  — отсутствие security-headers, устаревшие версии;
    --   info     — прочие наблюдения.
    severity        TEXT NOT NULL DEFAULT 'info',
    category        TEXT,                       -- admin_panel|secfile|headers|outdated|...
    title           TEXT NOT NULL,              -- краткое название находки
    detail          TEXT,                       -- подробности (что найдено)
    recommendation  TEXT,                       -- авто-рекомендация по устранению
    tool            TEXT,                       -- инструмент-источник
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Локальные пользователи NetInv для авторизации в web-приложении.
-- Заводятся install.sh при установке. Доступ разрешён только пользователям,
-- состоящим в группе 'cpt' (in_cpt=1).
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    pw_hash       TEXT NOT NULL,             -- werkzeug PBKDF2 hash
    in_cpt        INTEGER NOT NULL DEFAULT 1,-- членство в группе cpt
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_hosts_run ON hosts(run_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_webres_host ON webres(host_id);
CREATE INDEX IF NOT EXISTS idx_runs_target ON scan_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_tdomains_target ON target_domains(target_id);
CREATE INDEX IF NOT EXISTS idx_iporigin_target ON ip_origin(target_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_target ON discovered_subdomains(target_id);
CREATE INDEX IF NOT EXISTS idx_ipattrs_target ON ip_attributes(target_id);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulns(host_id);
"""


def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    with connect() as c:
        c.executescript(SCHEMA)
        _migrate(c)
        c.commit()
    _check_writable()


def _migrate(c):
    """Лёгкая миграция: добавить новые столбцы в существующие БД (без потери данных)."""
    hcols = {r["name"] for r in c.execute("PRAGMA table_info(hosts)")}
    if "alive_no_ports" not in hcols:
        c.execute("ALTER TABLE hosts ADD COLUMN alive_no_ports INTEGER NOT NULL DEFAULT 0")
    if "advanced_note" not in hcols:
        c.execute("ALTER TABLE hosts ADD COLUMN advanced_note TEXT")

    # scan_runs: класс сканирования и краткие опции
    rcols = {r["name"] for r in c.execute("PRAGMA table_info(scan_runs)")}
    if "scan_class" not in rcols:
        c.execute("ALTER TABLE scan_runs ADD COLUMN scan_class TEXT NOT NULL DEFAULT 'main'")
    if "options_json" not in rcols:
        c.execute("ALTER TABLE scan_runs ADD COLUMN options_json TEXT")

    # host_state: класс сканирования и признак присутствия.
    # ВНИМАНИЕ: в старой схеме был UNIQUE(target_id, ip); добавление
    # scan_class меняет ключ на (target_id, scan_class, ip). Для чистоты
    # пересобираем таблицу, если столбца scan_class ещё нет.
    hs_cols = {r["name"] for r in c.execute("PRAGMA table_info(host_state)")}
    if hs_cols and "scan_class" not in hs_cols:
        # Старые записи считаем результатами 'main' (ранее классов не было).
        c.execute("ALTER TABLE host_state RENAME TO host_state_old")
        c.executescript(_HOST_STATE_DDL)
        old_cols = hs_cols & {
            "target_id", "ip", "first_seen", "last_run_id", "prev_run_id",
            "prev2_run_id", "last_scanned_at", "prev_scanned_at",
            "prev2_scanned_at", "diff_prev", "diff_prev2"}
        cols_csv = ", ".join(sorted(old_cols))
        c.execute(
            f"INSERT INTO host_state(scan_class, {cols_csv}) "
            f"SELECT 'main', {cols_csv} FROM host_state_old")
        c.execute("DROP TABLE host_state_old")


# DDL таблицы host_state — используется при миграции (должен совпадать с SCHEMA).
_HOST_STATE_DDL = """
CREATE TABLE IF NOT EXISTS host_state (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_class      TEXT NOT NULL DEFAULT 'main',
    ip              TEXT NOT NULL,
    first_seen      TEXT,
    last_run_id     INTEGER,
    prev_run_id     INTEGER,
    prev2_run_id    INTEGER,
    last_scanned_at TEXT,
    prev_scanned_at TEXT,
    prev2_scanned_at TEXT,
    diff_prev       TEXT,
    diff_prev2      TEXT,
    presence        TEXT NOT NULL DEFAULT 'pres',
    UNIQUE(target_id, scan_class, ip)
);
"""


def _check_writable():
    """Проверяет, что в БД и каталог data/ действительно можно писать.

    Самая частая боевая ошибка: install.sh запущен под sudo, файл/каталог
    принадлежат root, а web запущен от обычного пользователя →
    'attempt to write a readonly database'. Даём понятную диагностику.
    """
    problems = []
    if not os.access(DB_DIR, os.W_OK | os.X_OK):
        problems.append(f"нет прав записи в каталог {DB_DIR}")
    if os.path.exists(DB_PATH) and not os.access(DB_PATH, os.W_OK):
        problems.append(f"нет прав записи в файл БД {DB_PATH}")
    if problems:
        import getpass
        user = getpass.getuser()
        raise PermissionError(
            "База данных недоступна для записи (текущий пользователь: "
            f"{user}): " + "; ".join(problems) + ".\n"
            "Вероятно, установка выполнялась от root (sudo), а запуск — "
            "от обычного пользователя. Исправьте владение каталога data/:\n"
            f"    sudo chown -R $(id -un):$(id -gn) {os.path.dirname(DB_DIR)}"
        )


@contextmanager
def connect():
    """Контекстный менеджер соединения с включённым row_factory."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        conn.close()


# ----------------------- targets -----------------------

def add_target(name, cidr, description=""):
    with _LOCK, connect() as c:
        cur = c.execute(
            "INSERT INTO targets(name, cidr, description) VALUES (?,?,?)",
            (name, cidr, description),
        )
        c.commit()
        return cur.lastrowid


def list_targets():
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM targets ORDER BY id DESC")]


def get_target(target_id):
    with connect() as c:
        r = c.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        return dict(r) if r else None


def delete_target(target_id):
    with _LOCK, connect() as c:
        c.execute("DELETE FROM targets WHERE id=?", (target_id,))
        c.commit()


# ----------------------- target_domains -----------------------

def add_target_domain(target_id, domain):
    """Привязать домен к объекту (без дубликатов). Домен нормализуется."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return None
    with _LOCK, connect() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO target_domains(target_id, domain) VALUES (?,?)",
            (target_id, domain))
        c.commit()
        return cur.lastrowid


def list_target_domains(target_id):
    """Домены объекта, отсортированные «по уровням» (требование 1)."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM target_domains WHERE target_id=?", (target_id,))]
    rows.sort(key=lambda r: domain_sort_key(r["domain"]))
    return rows


def domains_for_target(target_id):
    """Простой список доменных имён объекта (сортировка по уровням)."""
    with connect() as c:
        domains = [r["domain"] for r in c.execute(
            "SELECT domain FROM target_domains WHERE target_id=?", (target_id,))]
    domains.sort(key=domain_sort_key)
    return domains


def delete_target_domain(domain_id):
    with _LOCK, connect() as c:
        c.execute("DELETE FROM target_domains WHERE id=?", (domain_id,))
        c.commit()


# ----------------------- ip_origin (источник IP) -----------------------

def set_ip_origin(target_id, ip, source, domain=None):
    """Сохранить происхождение IP (cidr|domain|subdomain) и домен-источник.

    Приоритет: если IP уже имеет источник domain/subdomain (с именем),
    не перезаписываем его менее информативным 'cidr'. Именованный источник
    всегда побеждает безымянный диапазон.
    """
    domain = (domain or None)
    if domain:
        domain = domain.strip().lower().rstrip(".") or None
    with _LOCK, connect() as c:
        existing = c.execute(
            "SELECT source, domain FROM ip_origin WHERE target_id=? AND ip=?",
            (target_id, ip)).fetchone()
        if existing:
            # Не понижаем именованный источник до cidr без домена.
            if source == "cidr" and existing["domain"]:
                return
            c.execute(
                "UPDATE ip_origin SET source=?, domain=COALESCE(?, domain), "
                "updated_at=datetime('now') WHERE target_id=? AND ip=?",
                (source, domain, target_id, ip))
        else:
            c.execute(
                "INSERT INTO ip_origin(target_id, ip, source, domain) VALUES (?,?,?,?)",
                (target_id, ip, source, domain))
        c.commit()


def get_ip_origins(target_id):
    """Словарь {ip: {'source':..., 'domain':...}} для объекта."""
    with connect() as c:
        return {r["ip"]: {"source": r["source"], "domain": r["domain"]}
                for r in c.execute(
                    "SELECT ip, source, domain FROM ip_origin WHERE target_id=?",
                    (target_id,))}


# ----------------------- discovered_subdomains -----------------------

def add_subdomain(target_id, parent, subdomain, ip=None, tool=None, last_run_id=None):
    """Добавить/обновить найденный поддомен (без дубликатов по имени+IP)."""
    subdomain = (subdomain or "").strip().lower().rstrip(".")
    parent = (parent or "").strip().lower().rstrip(".")
    if not subdomain:
        return
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO discovered_subdomains(target_id, parent, subdomain, ip, "
            "tool, last_run_id) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(target_id, subdomain, ip) DO UPDATE SET "
            "tool=excluded.tool, last_run_id=excluded.last_run_id, "
            "found_at=datetime('now')",
            (target_id, parent, subdomain, ip, tool, last_run_id))
        c.commit()


def list_subdomains(target_id):
    """Найденные поддомены, отсортированные «по уровням» (требование 1):
    сначала по родительскому домену (по уровням), затем по самому
    поддомену (тоже по уровням)."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM discovered_subdomains WHERE target_id=?", (target_id,))]
    rows.sort(key=lambda r: (domain_sort_key(r["parent"]),
                             domain_sort_key(r["subdomain"])))
    return rows


# ----------------------- scan_runs -----------------------

def create_run(target_id, started_at, profile, nmap_args, scan_class="main",
               options_json=None):
    with _LOCK, connect() as c:
        cur = c.execute(
            "INSERT INTO scan_runs(target_id, started_at, profile, nmap_args, "
            "scan_class, options_json) VALUES (?,?,?,?,?,?)",
            (target_id, started_at, profile, nmap_args, scan_class, options_json),
        )
        c.commit()
        return cur.lastrowid


def finish_run(run_id, status, finished_at, hosts_up, log=""):
    with _LOCK, connect() as c:
        c.execute(
            "UPDATE scan_runs SET status=?, finished_at=?, hosts_up=?, log=? WHERE id=?",
            (status, finished_at, hosts_up, log, run_id),
        )
        c.commit()


def list_runs(target_id=None, limit=100, scan_class=None):
    """Список запусков. Если scan_class задан — фильтр по классу."""
    where = []
    params = []
    if target_id:
        where.append("r.target_id=?")
        params.append(target_id)
    if scan_class:
        where.append("r.scan_class=?")
        params.append(scan_class)
    wsql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with connect() as c:
        q = ("SELECT r.*, t.name AS target_name, t.cidr AS target_cidr "
             "FROM scan_runs r JOIN targets t ON t.id=r.target_id "
             f"{wsql} ORDER BY r.id DESC LIMIT ?")
        return [dict(r) for r in c.execute(q, params)]


def get_run(run_id):
    with connect() as c:
        r = c.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        return dict(r) if r else None


def prior_run_ids(target_id, before_run_id, n=2, scan_class=None):
    """Вернуть до n последних завершённых запусков по target ДО run_id.

    Если scan_class задан — учитываются только запуски того же класса
    (основное сравнивается только с основным, расширенное — с расширенным).
    """
    with connect() as c:
        if scan_class:
            rows = c.execute(
                "SELECT id FROM scan_runs WHERE target_id=? AND id<? AND "
                "status='done' AND scan_class=? ORDER BY id DESC LIMIT ?",
                (target_id, before_run_id, scan_class, n),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT id FROM scan_runs WHERE target_id=? AND id<? AND "
                "status='done' ORDER BY id DESC LIMIT ?",
                (target_id, before_run_id, n),
            ).fetchall()
        return [r["id"] for r in rows]


# ----------------------- hosts/ports/webres -----------------------

def add_host(run_id, ip, hostname, state, scanned_at, alive_no_ports=0):
    with _LOCK, connect() as c:
        cur = c.execute(
            "INSERT INTO hosts(run_id, ip, hostname, state, scanned_at, alive_no_ports) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, ip, hostname, state, scanned_at, int(alive_no_ports)),
        )
        c.commit()
        return cur.lastrowid


def set_host_advanced(host_id, note, alive_no_ports=None):
    """Сохранить пояснение advanced-проверки (и при необходимости флаг)."""
    with _LOCK, connect() as c:
        if alive_no_ports is None:
            c.execute("UPDATE hosts SET advanced_note=? WHERE id=?", (note, host_id))
        else:
            c.execute("UPDATE hosts SET advanced_note=?, alive_no_ports=? WHERE id=?",
                      (note, int(alive_no_ports), host_id))
        c.commit()


def add_port(host_id, port, proto, state, service, product, version, extrainfo, confidence):
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO ports(host_id, port, proto, state, service, product, version, "
            "extrainfo, confidence) VALUES (?,?,?,?,?,?,?,?,?)",
            (host_id, port, proto, state, service, product, version, extrainfo, confidence),
        )
        c.commit()


def add_webres(host_id, url, status_code, title, server, tech):
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO webres(host_id, url, status_code, title, server, tech) "
            "VALUES (?,?,?,?,?,?)",
            (host_id, url, status_code, title, server, tech),
        )
        c.commit()


def hosts_for_run(run_id):
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM hosts WHERE run_id=?", (run_id,))]
    rows.sort(key=lambda r: ip_sort_key(r["ip"]))
    return rows


def ports_for_host(host_id):
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM ports WHERE host_id=? ORDER BY port", (host_id,))]


def webres_for_host(host_id):
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM webres WHERE host_id=? ORDER BY url", (host_id,))]


def host_by_ip_in_run(run_id, ip):
    with connect() as c:
        r = c.execute("SELECT * FROM hosts WHERE run_id=? AND ip=?",
                      (run_id, ip)).fetchone()
        return dict(r) if r else None


# ----------------------- host_state -----------------------

def upsert_host_state(target_id, scan_class, ip, **fields):
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values())
    with _LOCK, connect() as c:
        existing = c.execute(
            "SELECT id FROM host_state WHERE target_id=? AND scan_class=? AND ip=?",
            (target_id, scan_class, ip)).fetchone()
        if existing:
            c.execute(f"UPDATE host_state SET {cols} WHERE id=?", vals + [existing["id"]])
        else:
            keys = ["target_id", "scan_class", "ip"] + list(fields.keys())
            ph = ",".join("?" * len(keys))
            c.execute(f"INSERT INTO host_state({','.join(keys)}) VALUES ({ph})",
                      [target_id, scan_class, ip] + list(fields.values()))
        c.commit()


def host_state_first_seen(target_id, scan_class, ip):
    with connect() as c:
        r = c.execute(
            "SELECT first_seen FROM host_state WHERE target_id=? AND scan_class=? AND ip=?",
            (target_id, scan_class, ip)).fetchone()
        return r["first_seen"] if r else None


def host_state_ips(target_id, scan_class):
    """Множество IP, уже известных в host_state для данного класса."""
    with connect() as c:
        return {r["ip"] for r in c.execute(
            "SELECT ip FROM host_state WHERE target_id=? AND scan_class=?",
            (target_id, scan_class))}


def report_rows(target_id, scan_class="main"):
    """Итоговая таблица по классу: одна строка на IP с историей и отличиями."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM host_state WHERE target_id=? AND scan_class=?",
            (target_id, scan_class))]
    # Числовая сортировка по возрастанию IP (а не лексикографическая)
    rows.sort(key=lambda r: ip_sort_key(r["ip"]))
    return rows


# ----------------------- ip_notes (редактируемое Описание) -----------------------

def get_ip_notes(target_id):
    """Словарь {ip: note} для всех IP объекта."""
    with connect() as c:
        return {r["ip"]: r["note"] for r in c.execute(
            "SELECT ip, note FROM ip_notes WHERE target_id=?", (target_id,))}


def get_ip_note(target_id, ip):
    with connect() as c:
        r = c.execute("SELECT note FROM ip_notes WHERE target_id=? AND ip=?",
                      (target_id, ip)).fetchone()
        return r["note"] if r else ""


def set_ip_note(target_id, ip, note):
    """Сохранить/обновить Описание в привязке к IP."""
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO ip_notes(target_id, ip, note, updated_at) "
            "VALUES (?,?,?, datetime('now')) "
            "ON CONFLICT(target_id, ip) DO UPDATE SET note=excluded.note, "
            "updated_at=datetime('now')",
            (target_id, ip, note))
        c.commit()


# ----------------------- ip_attributes (Администраторы / Контроль и защита) -----

# Имена флагов «Контроль и защита» (требование 4) — единый источник истины.
CTRL_FLAGS = ("ctrl_cpt", "ctrl_soc", "ctrl_vulnscan", "ctrl_waf", "ctrl_ddos")


def _empty_attrs():
    a = {"admins": ""}
    for f in CTRL_FLAGS:
        a[f] = 0
    return a


def get_ip_attributes(target_id):
    """Словарь {ip: {admins, ctrl_cpt, ctrl_soc, ...}} для всех IP объекта."""
    with connect() as c:
        out = {}
        for r in c.execute(
                "SELECT ip, admins, ctrl_cpt, ctrl_soc, ctrl_vulnscan, "
                "ctrl_waf, ctrl_ddos FROM ip_attributes WHERE target_id=?",
                (target_id,)):
            out[r["ip"]] = {
                "admins": r["admins"] or "",
                "ctrl_cpt": int(r["ctrl_cpt"]),
                "ctrl_soc": int(r["ctrl_soc"]),
                "ctrl_vulnscan": int(r["ctrl_vulnscan"]),
                "ctrl_waf": int(r["ctrl_waf"]),
                "ctrl_ddos": int(r["ctrl_ddos"]),
            }
        return out


def set_ip_attributes(target_id, ip, admins=None, **flags):
    """Сохранить/обновить атрибуты IP. admins — текст «Администраторы»;
    flags — любые из CTRL_FLAGS (0/1). Передавать можно частично:
    указанные поля обновляются, неуказанные сохраняют прежнее значение."""
    sets, vals = [], []
    if admins is not None:
        sets.append("admins=?")
        vals.append(admins)
    for f in CTRL_FLAGS:
        if f in flags and flags[f] is not None:
            sets.append(f"{f}=?")
            vals.append(int(bool(flags[f])))
    with _LOCK, connect() as c:
        existing = c.execute(
            "SELECT id FROM ip_attributes WHERE target_id=? AND ip=?",
            (target_id, ip)).fetchone()
        if existing:
            if sets:
                sets.append("updated_at=datetime('now')")
                c.execute(
                    f"UPDATE ip_attributes SET {', '.join(sets)} WHERE id=?",
                    vals + [existing["id"]])
        else:
            row = _empty_attrs()
            if admins is not None:
                row["admins"] = admins
            for f in CTRL_FLAGS:
                if f in flags and flags[f] is not None:
                    row[f] = int(bool(flags[f]))
            c.execute(
                "INSERT INTO ip_attributes(target_id, ip, admins, ctrl_cpt, "
                "ctrl_soc, ctrl_vulnscan, ctrl_waf, ctrl_ddos) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (target_id, ip, row["admins"], row["ctrl_cpt"], row["ctrl_soc"],
                 row["ctrl_vulnscan"], row["ctrl_waf"], row["ctrl_ddos"]))
        c.commit()


# ----------------------- vulns (уязвимости web-ресурсов) -----------------------

def add_vuln(host_id, severity, category, title, detail="", recommendation="",
             tool="", url=""):
    """Сохранить одну находку уязвимости/наблюдения для узла (требование 5)."""
    if severity not in ("critical", "warning", "info"):
        severity = "info"
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO vulns(host_id, url, severity, category, title, detail, "
            "recommendation, tool) VALUES (?,?,?,?,?,?,?,?)",
            (host_id, url, severity, category, title, detail, recommendation, tool))
        c.commit()


# Порядок сортировки по критичности (critical → warning → info).
_SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}


def vulns_for_host(host_id):
    """Находки узла, отсортированные по критичности (сначала critical)."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM vulns WHERE host_id=?", (host_id,))]
    rows.sort(key=lambda r: (_SEV_ORDER.get(r.get("severity"), 9),
                             r.get("category") or "", r.get("title") or ""))
    return rows


# ----------------------- users (авторизация) -----------------------

def get_user(username):
    with connect() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None


def list_users():
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, username, in_cpt, created_at FROM users ORDER BY username")]


def upsert_user(username, pw_hash, in_cpt=1):
    """Создать/обновить локального пользователя NetInv."""
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO users(username, pw_hash, in_cpt) VALUES (?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash, "
            "in_cpt=excluded.in_cpt",
            (username, pw_hash, int(in_cpt)))
        c.commit()


def count_users():
    with connect() as c:
        return c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


if __name__ == "__main__":
    init_db()
    print("DB initialized at", DB_PATH)
