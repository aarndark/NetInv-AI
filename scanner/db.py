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

import datetime as _dt
import ipaddress
import json
import os
import sqlite3
import threading
from contextlib import contextmanager


def _now():
    """Текущее время в ISO-формате (секундная точность) — единый источник
    временных меток для provenance и журналов ошибок v1.6.0."""
    return _dt.datetime.now().isoformat(timespec="seconds")


def ip_sort_key(ip):
    """Ключ для числовой сортировки IP по возрастанию (IPv4/IPv6).
    Некорректные значения уходят в конец."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def domain_sort_key(domain):
    """Ключ ИЕРАРХИЧЕСКОЙ сортировки доменов (требование 3 v1.5.0).

    Каждый домен идёт ВМЕСТЕ со своими поддоменами сразу под ним
    (родитель → его дети → следующий родитель), а НЕ «все 2-е уровни,
    потом все 3-и». Например:

        domaina.ru
        alpha.domaina.ru
        beta.domaina.ru
        delta.domaina.ru
        domainb.ru
        domainc.ru

    Реализация: ключ — кортеж меток СПРАВА НАЛЕВО (TLD первым).
    При сравнении кортежей более короткий префикс (родитель) всегда
    идёт раньше более длинного (его поддомены), и поддомены одного
    родителя группируются вместе — именно та, что нужно.

    Дублируется в dns_recon.domain_sort_key — здесь оставлена
    самодостаточная копия, чтобы db.py не зависел от модуля разведки.
    """
    norm = (domain or "").strip().lower().rstrip(".")
    labels = [p for p in norm.split(".") if p]
    return tuple(reversed(labels))

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
    options_json TEXT,
    -- v1.6.0 (треб. 2): полный набор опций запуска (и main, и advanced) —
    -- для колонки «Опции» → раскрывающийся список «опции» на странице истории.
    options_full_json TEXT,
    -- v1.6.0 (треб. 2): модули, УСПЕШНО применённые с учётом graceful
    -- degradation (JSON-список {module,status,reason}). Дублирует таблицу
    -- scan_modules для быстрого рендера раскрывающегося списка «модули».
    modules_json TEXT,
    -- v1.6.0 (треб. 4): абсолютный путь к файлу лога этого запуска
    -- (для «ссылки на лог» в статистике истории).
    log_path TEXT,
    -- v1.6.6 (П.1): пофазовый статус запуска (JSON-объект
    -- {"dns":"ok|off","nmap":"ok|failed","webscan":"ok|skipped|off", ...},
    -- может включать необязательные *_note поля) — для отображения
    -- ok/failed/skipped по этапам в колонке «Ошибки сканирования».
    phases_json TEXT
);

-- v1.6.0 (треб. 3): ошибки сканирования по модулям. Фиксируются ОЧЕВИДНЫЕ
-- ошибки инструментов (недоступность онлайн-CVE БД, HTTP 400 OSV, сбои
-- парсинга и т.п.). Недоступность хостов и обычные результаты скана СЮДА
-- НЕ вносятся. Каждая строка привязана к запуску и модулю (nmap/dalfox/
-- nikto/osv/cve/webscan/...).
CREATE TABLE IF NOT EXISTS scan_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    module      TEXT NOT NULL,               -- nmap|dalfox|nikto|osv|cve|webscan|dns|...
    kind        TEXT NOT NULL DEFAULT 'error', -- error|degraded (инфо о graceful degradation)
    message     TEXT NOT NULL,               -- краткое сообщение об ошибке
    detail      TEXT,                        -- подробности (URL/продукт/исключение)
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- v1.6.0 (треб. 2): модули, задействованные в запуске, и их статус с учётом
-- graceful degradation. status: used|skipped_missing|skipped_degraded|off.
CREATE TABLE IF NOT EXISTS scan_modules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    module      TEXT NOT NULL,               -- nmap|nse|nse_vulners|whatweb|nikto|wpscan|dalfox|cve_online|cve_offline|dns_recon|dns_brute|dig_rdns|...
    status      TEXT NOT NULL DEFAULT 'used', -- used|skipped_missing|skipped_degraded|off
    reason      TEXT,                        -- пояснение (почему пропущен/деградировал)
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(run_id, module)
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
    -- v1.6.0 (треб. 5): происхождение обнаружения поддомена во времени.
    -- Утилит может быть несколько (напр. dnsmap и dnsrecon дали разные IP —
    -- конфликт разрешается через resolve). Храним первое/последнее обнаружение
    -- и инструменты, а также агрегированный список утилит.
    first_seen  TEXT,                        -- дата первого обнаружения
    first_tool  TEXT,                        -- утилита первого обнаружения
    last_seen   TEXT,                        -- дата последнего обнаружения
    last_tool   TEXT,                        -- утилита последнего обнаружения
    tools       TEXT,                        -- все утилиты, обнаружившие (через запятую)
    resolved_ip TEXT,                        -- IP после разрешения конфликта (resolve)
    -- v1.6.1 (правка 3): конфликты IP разрешаются АВТОМАТИЧЕСКИ, поэтому
    -- каждый поддомен присутствует в таблице ОДИН раз. alt_ips — прочие IP,
    -- отброшенные при авторазрешении (для сводки в столбце «Информация»);
    -- auto_resolved=1, если текущий IP выбран автоматически из конфликта.
    alt_ips     TEXT,                        -- альтернативные IP (через запятую)
    auto_resolved INTEGER NOT NULL DEFAULT 0,
    -- bound: поддомен привязан к объекту как подтверждённая цель (0/1).
    bound       INTEGER NOT NULL DEFAULT 0,
    -- present: обнаружен в ПОСЛЕДНЕМ скане (0/1) — для подсветки новых/исчезших.
    present     INTEGER NOT NULL DEFAULT 1,
    -- v1.6.4 (Правка 1): is_artifact=1 — поддомен НЕ прошёл проверку
    -- соответствия IP (прямая/обратная) и считается артефактом
    -- обнаружения (wildcard/catch-all). Смещается вниз таблицы и не
    -- привязывается кнопкой «Привязать все новые».
    is_artifact INTEGER NOT NULL DEFAULT 0,
    -- verify_reason: человекочитаемая причина вердикта проверки.
    verify_reason TEXT,
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
    severity_reason TEXT,                       -- обоснование уровня severity (треб. 3)
    -- CVE-сведения (требование 3б): сопоставление версии ПО с известными
    -- уязвимостями (offline-таблица + онлайн NVD/OSV + nmap NSE vulners).
    cve_id          TEXT,                       -- идентификатор(ы) CVE (через запятую)
    cvss            TEXT,                       -- оценка CVSS (например, 9.8)
    cve_source      TEXT,                       -- источник: offline|nvd|osv|vulners
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- v1.6.5 (П.11): состояние разбора уязвимостей на уровне ОБЪЕКТА (target),
-- устойчивое между сканами. Ключ vkey = "<ip>|<port>|<cve_id|title>"
-- (IP + порт + название/CVE) — по нему уязвимость опознаётся в новых сканах.
--   state='hidden'   — скрыта (принятие риска или ошибка детекции): по
--                      умолчанию не отображается в таблицах и не учитывается
--                      в статистике; при повторных сканах скрывается
--                      автоматически.
--   state='accepted' — принята в работу: попадает на страницу «Разбор
--                      уязвимостей».
-- comment — сохраняемый комментарий аналитика (для accepted).
-- Снимки полей (ip/port/title/cve_id/severity/detail/...) сохраняются, чтобы
-- страница «Разбор» и авто-скрытие работали независимо от текущего запуска.
CREATE TABLE IF NOT EXISTS vuln_states (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    vkey         TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'accepted',   -- hidden | accepted
    comment      TEXT,
    ip           TEXT,
    port         TEXT,
    title        TEXT,
    cve_id       TEXT,
    cvss         TEXT,
    severity     TEXT,
    detail       TEXT,
    recommendation TEXT,
    tool         TEXT,
    url          TEXT,
    log_run_id   INTEGER,                             -- запуск, из которого принята (для «открыть лог»)
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, vkey)
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
CREATE INDEX IF NOT EXISTS idx_vulnstates_target ON vuln_states(target_id);
CREATE INDEX IF NOT EXISTS idx_scanerrors_run ON scan_errors(run_id);
CREATE INDEX IF NOT EXISTS idx_scanmodules_run ON scan_modules(run_id);
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

    # vulns: обоснование severity и CVE-сведения (требования 3, 3б).
    vcols = {r["name"] for r in c.execute("PRAGMA table_info(vulns)")}
    for col in ("severity_reason", "cve_id", "cvss", "cve_source"):
        if col not in vcols:
            c.execute(f"ALTER TABLE vulns ADD COLUMN {col} TEXT")

    # v1.6.0 (треб. 2, 4): полный набор опций, список модулей и
    # путь к логу в scan_runs.
    # v1.6.6 (П.1): пофазовый статус запуска (dns/nmap/webscan ->
    # ok|failed|skipped|off) — JSON, для колонки «Ошибки сканирования»
    # страницы «История сканирований».
    for col in ("options_full_json", "modules_json", "log_path", "phases_json"):
        if col not in rcols:
            c.execute(f"ALTER TABLE scan_runs ADD COLUMN {col} TEXT")

    # v1.6.0 (треб. 5): provenance-поля поддоменов (первое/последнее
    # обнаружение, инструменты, привязка, присутствие, разрешённый IP).
    scols = {r["name"] for r in c.execute(
        "PRAGMA table_info(discovered_subdomains)")}
    if scols:  # таблица уже существует — добавляем недостающие столбцы
        for col, ddl in (("first_seen", "TEXT"), ("first_tool", "TEXT"),
                         ("last_seen", "TEXT"), ("last_tool", "TEXT"),
                         ("tools", "TEXT"), ("resolved_ip", "TEXT"),
                         ("bound", "INTEGER NOT NULL DEFAULT 0"),
                         ("present", "INTEGER NOT NULL DEFAULT 1"),
                         # v1.6.1 (правка 3): автоматическое разрешение конфликтов.
                         # alt_ips  — альтернативные IP, отброшенные при авторазрешении
                         #            (через запятую), для сводки в столбце «Информация».
                         # auto_resolved — 1, если IP выбран автоматически из конфликта.
                         ("alt_ips", "TEXT"),
                         ("auto_resolved", "INTEGER NOT NULL DEFAULT 0"),
                         # v1.6.4 (Правка 1): верификация поддоменов по IP.
                         # is_artifact  — 1, если поддомен не прошёл прямую/
                         #                обратную проверку соответствия IP.
                         # verify_reason — человекочитаемая причина вердикта.
                         ("is_artifact", "INTEGER NOT NULL DEFAULT 0"),
                         ("verify_reason", "TEXT")):
            if col not in scols:
                c.execute(f"ALTER TABLE discovered_subdomains ADD COLUMN {col} {ddl}")

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

def add_subdomain(target_id, parent, subdomain, ip=None, tool=None, last_run_id=None,
                  is_artifact=0, verify_reason=None):
    """Добавить/обновить найденный поддомен (без дубликатов по имени+IP).

    v1.6.0 (треб. 5): ведём provenance — первое/последнее обнаружение,
    инструменты (может быть несколько), агрегированный список утилит.
    Новый поддомен помечается present=1; привязка (bound) не меняется.

    v1.6.4 (Правка 1): is_artifact/verify_reason — результат проверки
    соответствия IP (прямая/обратная). Обновляются при каждом скане.
    """
    subdomain = (subdomain or "").strip().lower().rstrip(".")
    parent = (parent or "").strip().lower().rstrip(".")
    if not subdomain:
        return
    is_artifact = 1 if is_artifact else 0
    now = _now()
    with _LOCK, connect() as c:
        existing = c.execute(
            "SELECT id, tools FROM discovered_subdomains "
            "WHERE target_id=? AND subdomain=? AND ip IS ?",
            (target_id, subdomain, ip)).fetchone()
        if existing:
            # Агрегируем список утилит (без дубликатов).
            tools = [t for t in (existing["tools"] or "").split(",") if t]
            if tool and tool not in tools:
                tools.append(tool)
            c.execute(
                "UPDATE discovered_subdomains SET tool=?, last_run_id=?, "
                "found_at=?, last_seen=?, last_tool=?, tools=?, present=1, "
                "is_artifact=?, verify_reason=? "
                "WHERE id=?",
                (tool, last_run_id, now, now, tool, ",".join(tools),
                 is_artifact, verify_reason, existing["id"]))
        else:
            c.execute(
                "INSERT INTO discovered_subdomains(target_id, parent, subdomain, "
                "ip, tool, last_run_id, found_at, first_seen, first_tool, "
                "last_seen, last_tool, tools, present, is_artifact, verify_reason) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
                (target_id, parent, subdomain, ip, tool, last_run_id, now,
                 now, tool, now, tool, tool or "", is_artifact, verify_reason))
        c.commit()


def list_subdomains(target_id):
    """Найденные поддомены, отсортированные «по уровням» (требование 1):
    сначала по родительскому домену (по уровням), затем по самому
    поддомену (тоже по уровням).

    v1.6.4 (Правка 1): артефакты обнаружения (is_artifact=1) смещаются
    ВНИЗ таблицы — в ключ сортировки первым компонентом идёт
    is_artifact (0 раньше 1)."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM discovered_subdomains WHERE target_id=?", (target_id,))]
    rows.sort(key=lambda r: (int(r.get("is_artifact") or 0),
                             domain_sort_key(r["parent"]),
                             domain_sort_key(r["subdomain"])))
    return rows


def subdomain_conflicts(target_id):
    """v1.6.0 (треб. 5): множество FQDN, для которых записано
    несколько РАЗНЫХ IP (конфликт dnsmap vs dnsrecon — требует resolve)."""
    with connect() as c:
        rows = c.execute(
            "SELECT subdomain, COUNT(DISTINCT ip) AS n FROM discovered_subdomains "
            "WHERE target_id=? AND ip IS NOT NULL GROUP BY subdomain "
            "HAVING n > 1", (target_id,)).fetchall()
    return {r["subdomain"] for r in rows}


def set_subdomain_bound(target_id, subdomain, bound):
    """Привязать/отвязать поддомен к объекту (треб. 5, по одному)."""
    subdomain = (subdomain or "").strip().lower().rstrip(".")
    with _LOCK, connect() as c:
        c.execute(
            "UPDATE discovered_subdomains SET bound=? WHERE target_id=? AND subdomain=?",
            (1 if bound else 0, target_id, subdomain))
        c.commit()


def set_all_subdomains_bound(target_id, bound, only_present=True):
    """Массовая привязка/отвязка (треб. 5, «все одной кнопкой»).

    bound=True — привязать НОВЫЕ обнаруженные (present=1) поддомены с IP;
    bound=False — отвязать ИСЧЕЗНУВШИЕ (present=0). Возвращает число изменённых.

    v1.6.4 (Правка 1): при bound=True артефакты обнаружения
    (is_artifact=1) ИСКЛЮЧАЮТСЯ — кнопка «Привязать все новые»
    на них не распространяется.
    """
    with _LOCK, connect() as c:
        if bound:
            cur = c.execute(
                "UPDATE discovered_subdomains SET bound=1 "
                "WHERE target_id=? AND bound=0 AND ip IS NOT NULL "
                "AND is_artifact=0"
                + (" AND present=1" if only_present else ""),
                (target_id,))
        else:
            cur = c.execute(
                "UPDATE discovered_subdomains SET bound=0 "
                "WHERE target_id=? AND bound=1"
                + (" AND present=0" if only_present else ""),
                (target_id,))
        c.commit()
        return cur.rowcount


def sync_bound_domains_to_target(target_id):
    """v1.6.5 (доработка 6, исторически) / v1.6.7 (испр. бага 1):
    синхронизировать привязанные (bound=1) поддомены в таблицу
    target_domains, чтобы они отображались в столбце «Домены» на странице
    «Объекты сканирования» и участвовали в будущих сканированиях
    (как домены 3+ уровня — только резолв IP, без повторного поиска
    поддоменов).

    v1.6.7: раньше синхронизировался только parent (родительский
    домен 2-го уровня) — он практически всегда уже есть в target_domains
    (именно он и использовался для поиска поддоменов), из-за чего
    кнопка «Привязать все новые» ничего реально не добавляла и столбец
    «Домены» не обновлялся. Сейчас добавляется сам привязанный
    поддомен (FQDN), а также его parent — на всякий случай, если он по
    какой-то причине ещё не был привязан.

    Каждый добавляется через add_target_domain (INSERT OR IGNORE —
    без дубликатов). Возвращает число реально добавленных новых
    доменов.
    """
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT subdomain, parent FROM discovered_subdomains "
            "WHERE target_id=? AND bound=1", (target_id,))]
    candidates = set()
    for r in rows:
        sub = (r.get("subdomain") or "").strip().lower().rstrip(".")
        if sub:
            candidates.add(sub)
        parent = (r.get("parent") or "").strip().lower().rstrip(".")
        if parent:
            candidates.add(parent)
    existing = set(domains_for_target(target_id))
    added = 0
    for d in sorted(candidates):
        if d not in existing:
            add_target_domain(target_id, d)
            added += 1
    return added


def resolve_subdomain_ip(target_id, subdomain, resolved_ip, tool="resolve"):
    """v1.6.0 (треб. 5): разрешить конфликт разных IP.

    Схлопывает все записи данного FQDN в одну с подтверждённым IP
    (resolved_ip), сохраняя агрегированный список утилит и provenance.
    """
    subdomain = (subdomain or "").strip().lower().rstrip(".")
    with _LOCK, connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM discovered_subdomains WHERE target_id=? AND subdomain=?",
            (target_id, subdomain))]
        if not rows:
            return
        tools = []
        for r in rows:
            for t in (r.get("tools") or r.get("tool") or "").split(","):
                if t and t not in tools:
                    tools.append(t)
        if tool and tool not in tools:
            tools.append(tool)
        first_seen = min((r.get("first_seen") or r.get("found_at") or "")
                         for r in rows)
        keep = rows[0]
        # Удаляем все дубликаты, оставляем одну запись.
        c.execute("DELETE FROM discovered_subdomains WHERE target_id=? AND subdomain=?",
                  (target_id, subdomain))
        now = _now()
        c.execute(
            "INSERT INTO discovered_subdomains(target_id, parent, subdomain, ip, "
            "tool, last_run_id, found_at, first_seen, first_tool, last_seen, "
            "last_tool, tools, resolved_ip, bound, present) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, keep.get("parent"), subdomain, resolved_ip, tool,
             keep.get("last_run_id"), now, first_seen or now,
             keep.get("first_tool"), now, tool, ",".join(tools), resolved_ip,
             int(keep.get("bound") or 0), 1))
        c.commit()


def auto_resolve_subdomains(target_id):
    """v1.6.1 (правка 3): АВТОМАТИЧЕСКОЕ разрешение конфликтов IP.

    Раньше при разных IP от разных утилит (dnsmap vs dnsrecon) в таблице
    оставалось НЕСКОЛЬКО строк одного FQDN, а оператору предлагался
    ручной resolve. Теперь каждая пара домен–IP присутствует ОДИН раз:
    для каждого FQDN автоматически выбирается ОДИН актуальный IP — наиболее
    свежий (по last_seen), при равенстве — подтверждённый большим
    числом утилит. Остальные IP сохраняются в alt_ips (для сводки
    в столбце «Информация»), все утилиты агрегируются в tools.
    Возвращает число разрешённых конфликтов.
    """
    resolved = 0
    with _LOCK, connect() as c:
        # Собираем FQDN, у которых больше одной строки (независимо от IP).
        names = [r["subdomain"] for r in c.execute(
            "SELECT subdomain, COUNT(*) AS n FROM discovered_subdomains "
            "WHERE target_id=? GROUP BY subdomain HAVING n > 1",
            (target_id,)).fetchall()]
        for name in names:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM discovered_subdomains "
                "WHERE target_id=? AND subdomain=?", (target_id, name))]
            if len(rows) < 2:
                continue
            # Агрегация утилит и времён.
            tools = []
            for r in rows:
                for t in (r.get("tools") or r.get("tool") or "").split(","):
                    t = t.strip()
                    if t and t not in tools:
                        tools.append(t)
            first_seen = min((r.get("first_seen") or r.get("found_at") or "")
                             for r in rows)
            last_seen = max((r.get("last_seen") or r.get("found_at") or "")
                            for r in rows)
            # Если оператор уже выбрал IP вручную (resolved_ip) — уважаем его.
            manual_ip = next((r.get("resolved_ip") for r in rows
                              if r.get("resolved_ip")), None)
            # Кандидаты IP с метаданными для выбора актуального.
            ip_rows = [r for r in rows if r.get("ip")]
            all_ips = []
            for r in ip_rows:
                if r["ip"] not in all_ips:
                    all_ips.append(r["ip"])
            if manual_ip:
                chosen = manual_ip
            elif ip_rows:
                # Сортировка: свежее last_seen → больше утилит → IP асц.
                def _key(r):
                    ntools = len([t for t in (r.get("tools") or "").split(",") if t])
                    return (r.get("last_seen") or r.get("found_at") or "",
                            ntools, r.get("ip") or "")
                chosen = sorted(ip_rows, key=_key, reverse=True)[0]["ip"]
            else:
                chosen = None
            alt = [ip for ip in all_ips if ip != chosen]
            keep = rows[0]
            was_conflict = len(all_ips) > 1 or bool(manual_ip and alt)
            # Схлопываем все строки FQDN в одну.
            bound = 1 if any(int(r.get("bound") or 0) for r in rows) else 0
            present = 1 if any(int(r.get("present") or 0) for r in rows) else 0
            last_run_id = next((r.get("last_run_id") for r in rows
                                if r.get("last_run_id")), keep.get("last_run_id"))
            c.execute("DELETE FROM discovered_subdomains "
                      "WHERE target_id=? AND subdomain=?", (target_id, name))
            c.execute(
                "INSERT INTO discovered_subdomains(target_id, parent, subdomain, "
                "ip, tool, last_run_id, found_at, first_seen, first_tool, "
                "last_seen, last_tool, tools, resolved_ip, alt_ips, "
                "auto_resolved, bound, present) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target_id, keep.get("parent"), name, chosen,
                 keep.get("tool"), last_run_id, keep.get("found_at") or first_seen,
                 first_seen, keep.get("first_tool"), last_seen,
                 keep.get("last_tool"), ",".join(tools),
                 manual_ip, ",".join(alt),
                 1 if (was_conflict and not manual_ip) else 0,
                 bound, present))
            if was_conflict:
                resolved += 1
        c.commit()
    return resolved


def mark_subdomains_run(target_id, run_id, since=None):
    """v1.6.0 (треб. 5): после DNS-разведки пометить present=1 те
    поддомены, что встретились в текущем запуске, а остальные — present=0
    («исчезли»). Вызывается в конце разведки объекта.

    Поскольку разведка идёт ДО создания записи запуска, add_subdomain
    не знает run_id. Поэтому «обнаруженными сейчас» считаем те, чьё
    last_seen >= since (время старта скана). Всем таким поддоменам
    проставляем last_run_id. Если since не задан — фоллбек на last_run_id.
    """
    with _LOCK, connect() as c:
        c.execute(
            "UPDATE discovered_subdomains SET present=0 WHERE target_id=?",
            (target_id,))
        if since:
            c.execute(
                "UPDATE discovered_subdomains SET present=1, last_run_id=? "
                "WHERE target_id=? AND last_seen>=?",
                (run_id, target_id, since))
        else:
            c.execute(
                "UPDATE discovered_subdomains SET present=1 "
                "WHERE target_id=? AND last_run_id=?", (target_id, run_id))
        c.commit()


# ----------------------- scan_runs -----------------------

def create_run(target_id, started_at, profile, nmap_args, scan_class="main",
               options_json=None, options_full_json=None, modules_json=None):
    with _LOCK, connect() as c:
        cur = c.execute(
            "INSERT INTO scan_runs(target_id, started_at, profile, nmap_args, "
            "scan_class, options_json, options_full_json, modules_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (target_id, started_at, profile, nmap_args, scan_class,
             options_json, options_full_json, modules_json),
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


def set_run_options_full(run_id, options_full_json):
    """v1.6.0 (треб. 2): сохранить полный набор опций запуска."""
    with _LOCK, connect() as c:
        c.execute("UPDATE scan_runs SET options_full_json=? WHERE id=?",
                  (options_full_json, run_id))
        c.commit()


def set_run_log_path(run_id, log_path):
    """v1.6.0 (треб. 4): сохранить абсолютный путь к логу запуска."""
    if run_id is None:
        return
    with _LOCK, connect() as c:
        c.execute("UPDATE scan_runs SET log_path=? WHERE id=?",
                  (log_path, run_id))
        c.commit()


def set_run_modules_json(run_id, modules_json):
    """v1.6.0 (треб. 2): сохранить JSON-список модулей запуска
    (дублирует scan_modules для быстрого рендера раскрывающегося списка)."""
    with _LOCK, connect() as c:
        c.execute("UPDATE scan_runs SET modules_json=? WHERE id=?",
                  (modules_json, run_id))
        c.commit()


def set_run_phases_json(run_id, phases_json):
    """v1.6.6 (П.1): сохранить пофазовый статус запуска (dns/nmap/webscan)
    для колонки «Ошибки сканирования» страницы «История сканирований».
    run_id может быть None на очень ранней стадии — тогда не пишем."""
    if run_id is None:
        return
    with _LOCK, connect() as c:
        c.execute("UPDATE scan_runs SET phases_json=? WHERE id=?",
                  (phases_json, run_id))
        c.commit()


def delete_run(run_id):
    """v1.6.0 (треб. 1): удалить нерепрезентативный запуск из БД.

    Связанные hosts/ports/webres/vulns/scan_errors/scan_modules удаляются
    каскадом (ON DELETE CASCADE). После удаления host_state может
    ссылаться на несуществующие last/prev/prev2 run_id — чистим
    ссылки и last_run_id у поддоменов. Возвращает (target_id, scan_class)
    удалённого запуска, чтобы вызывающая сторона могла пересчитать
    состояния узлов.
    """
    with _LOCK, connect() as c:
        row = c.execute("SELECT target_id, scan_class FROM scan_runs WHERE id=?",
                        (run_id,)).fetchone()
        if not row:
            return None
        target_id, scan_class = row["target_id"], row["scan_class"]
        # Снять ссылки из host_state (чтобы не указывали на удалённый запуск).
        c.execute("UPDATE host_state SET last_run_id=NULL WHERE last_run_id=?", (run_id,))
        c.execute("UPDATE host_state SET prev_run_id=NULL WHERE prev_run_id=?", (run_id,))
        c.execute("UPDATE host_state SET prev2_run_id=NULL WHERE prev2_run_id=?", (run_id,))
        c.execute("UPDATE discovered_subdomains SET last_run_id=NULL WHERE last_run_id=?",
                  (run_id,))
        # Сам запуск (каскад удалит hosts/ports/webres/vulns/scan_errors/scan_modules).
        c.execute("DELETE FROM scan_runs WHERE id=?", (run_id,))
        c.commit()
        return (target_id, scan_class)


def reset_database():
    """v1.6.0 (треб. 6а, netinv -dbreset): обнулить всю историю
    сканирований.

    УДАЛЯЕМ: scan_runs (каскадом hosts/ports/webres/vulns/scan_errors/
    scan_modules), host_state, ip_origin, discovered_subdomains.
    СОХРАНЯЕМ: users, targets, target_domains, ip_notes, ip_attributes,
    и файлы ./logs (они не в БД). Возвращает число удалённых запусков.
    """
    with _LOCK, connect() as c:
        n = c.execute("SELECT COUNT(*) AS n FROM scan_runs").fetchone()["n"]
        # Каскад от scan_runs снимет hosts/ports/webres/vulns/scan_errors/scan_modules.
        c.execute("DELETE FROM scan_runs")
        c.execute("DELETE FROM host_state")
        c.execute("DELETE FROM ip_origin")
        c.execute("DELETE FROM discovered_subdomains")
        c.commit()
        return n


# ----------------------- scan_errors (v1.6.0, треб. 3) -----------------------

def add_scan_error(run_id, module, message, detail=None, kind="error"):
    """Зафиксировать очевидную ошибку инструмента/модуля (треб. 3).

    kind='error'    — настоящая ошибка (недоступность онлайн-CVE БД,
                      HTTP 400 OSV, сбой парсинга и т.п.).
    kind='degraded' — инфо о graceful degradation (модуль не применялся).
    run_id может быть None на ранней стадии (до create_run) — тогда не пишем.
    """
    if run_id is None:
        return
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO scan_errors(run_id, module, kind, message, detail, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, module, kind, message, detail, _now()))
        c.commit()


def errors_for_run(run_id):
    """Ошибки запуска, сгруппированные по модулю (для раскрывающихся
    списков в колонке «Ошибки сканирования»)."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM scan_errors WHERE run_id=? ORDER BY module, id",
            (run_id,))]
    grouped = {}
    for r in rows:
        grouped.setdefault(r["module"], []).append(r)
    return grouped


# ----------------------- scan_modules (v1.6.0, треб. 2) -----------------------

def set_scan_module(run_id, module, status="used", reason=None):
    """Зафиксировать статус модуля в запуске (треб. 2).

    status: used|skipped_missing|skipped_degraded|off. Повторный вызов для
    того же (run_id, module) обновляет запись (UPSERT). run_id может
    быть None на ранней стадии — тогда не пишем.
    """
    if run_id is None:
        return
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO scan_modules(run_id, module, status, reason, created_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(run_id, module) DO UPDATE SET status=excluded.status, "
            "reason=excluded.reason",
            (run_id, module, status, reason, _now()))
        c.commit()


def modules_for_run(run_id):
    """Список модулей запуска с их статусами (треб. 2)."""
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM scan_modules WHERE run_id=? ORDER BY module",
            (run_id,))]


def get_run_full(run_id):
    """v1.6.0: запуск со всеми полями + имя/CIDR объекта, модули и
    сгруппированные ошибки — для рендера истории/текущего скана."""
    with connect() as c:
        r = c.execute(
            "SELECT r.*, t.name AS target_name, t.cidr AS target_cidr "
            "FROM scan_runs r JOIN targets t ON t.id=r.target_id WHERE r.id=?",
            (run_id,)).fetchone()
        if not r:
            return None
        run = dict(r)
    run["modules"] = modules_for_run(run_id)
    run["errors"] = errors_for_run(run_id)
    # v1.6.6 (П.1): пофазовый статус (dns/nmap/webscan -> ok|failed|skipped|off).
    try:
        run["phases"] = json.loads(run.get("phases_json") or "{}")
    except (ValueError, TypeError):
        run["phases"] = {}
    return run


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


def clear_host_state(target_id, scan_class):
    """v1.6.0 (треб. 1): удалить все строки host_state объекта в рамках
    класса. Нужно для полного пересчёта состояний после удаления запуска."""
    with _LOCK, connect() as c:
        c.execute("DELETE FROM host_state WHERE target_id=? AND scan_class=?",
                  (target_id, scan_class))
        c.commit()


def run_ids_asc(target_id, scan_class):
    """v1.6.0 (треб. 1): id завершённых запусков объекта данного класса
    в ХРОНОЛОГИЧЕСКОМ порядке (для повторного проигрывания при пересчёте
    host_state после удаления одного из запусков)."""
    with connect() as c:
        return [r["id"] for r in c.execute(
            "SELECT id FROM scan_runs WHERE target_id=? AND scan_class=? "
            "ORDER BY id ASC", (target_id, scan_class))]


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
             tool="", url="", severity_reason="", cve_id="", cvss="",
             cve_source=""):
    """Сохранить одну находку уязвимости/наблюдения для узла (требования 5, 3, 3б).

    severity_reason — обоснование выбранного уровня severity (треб. 3);
    cve_id/cvss/cve_source — сведения о CVE для версии ПО (треб. 3б).
    """
    if severity not in ("critical", "warning", "info"):
        severity = "info"
    with _LOCK, connect() as c:
        c.execute(
            "INSERT INTO vulns(host_id, url, severity, category, title, detail, "
            "recommendation, tool, severity_reason, cve_id, cvss, cve_source) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (host_id, url, severity, category, title, detail, recommendation,
             tool, severity_reason, cve_id, cvss, cve_source))
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


def vuln_severity_counts(run_id):
    """Сводка по уровням severity для всех узлов запуска (треб. 7).

    Возвращает dict с ключами crit/warn/info — число находок каждого
    уровня, собранных по всем узлам данного запуска.
    """
    with connect() as c:
        rows = c.execute(
            "SELECT v.severity AS sev, COUNT(*) AS n FROM vulns v "
            "JOIN hosts h ON h.id = v.host_id "
            "WHERE h.run_id=? GROUP BY v.severity", (run_id,)).fetchall()
    out = {"crit": 0, "warn": 0, "info": 0}
    for r in rows:
        sev = r["sev"]
        if sev == "critical":
            out["crit"] = r["n"]
        elif sev == "warning":
            out["warn"] = r["n"]
        else:
            out["info"] = r["n"]
    return out


# ----------------------- разбор уязвимостей (v1.6.5, П.11) -----------------------

def vuln_state_key(ip, port, cve_id="", title=""):
    """Ключ уязвимости для устойчивого скрытия/принятия между сканами.

    П.11: «одна и та же» уязвимость = IP + порт + название/CVE.
    Если есть CVE — используем его (стабильнее названия), иначе — title.
    """
    ip = (ip or "").strip()
    port = str(port or "").strip()
    ident = (cve_id or "").strip() or (title or "").strip()
    return f"{ip}|{port}|{ident}"


def get_vuln_states(target_id):
    """Словарь vkey -> запись состояния для объекта (для быстрого lookup)."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM vuln_states WHERE target_id=?", (target_id,))]
    return {r["vkey"]: r for r in rows}


def set_vuln_state(target_id, vkey, state, *, ip="", port="", title="",
                   cve_id="", cvss="", severity="", detail="",
                   recommendation="", tool="", url="", log_run_id=None,
                   comment=None):
    """Задать/обновить состояние уязвимости (hidden|accepted).

    При повторном вызове обновляет state и снимки полей; comment
    обновляется только если передан явно (не None).
    """
    if state not in ("hidden", "accepted"):
        raise ValueError("state должен быть 'hidden' или 'accepted'")
    with _LOCK, connect() as c:
        exists = c.execute(
            "SELECT id FROM vuln_states WHERE target_id=? AND vkey=?",
            (target_id, vkey)).fetchone()
        if exists:
            if comment is None:
                c.execute(
                    "UPDATE vuln_states SET state=?, ip=?, port=?, title=?, "
                    "cve_id=?, cvss=?, severity=?, detail=?, recommendation=?, "
                    "tool=?, url=?, log_run_id=COALESCE(?, log_run_id), "
                    "updated_at=datetime('now') WHERE target_id=? AND vkey=?",
                    (state, ip, port, title, cve_id, cvss, severity, detail,
                     recommendation, tool, url, log_run_id, target_id, vkey))
            else:
                c.execute(
                    "UPDATE vuln_states SET state=?, comment=?, ip=?, port=?, "
                    "title=?, cve_id=?, cvss=?, severity=?, detail=?, "
                    "recommendation=?, tool=?, url=?, "
                    "log_run_id=COALESCE(?, log_run_id), "
                    "updated_at=datetime('now') WHERE target_id=? AND vkey=?",
                    (state, comment, ip, port, title, cve_id, cvss, severity,
                     detail, recommendation, tool, url, log_run_id,
                     target_id, vkey))
        else:
            c.execute(
                "INSERT INTO vuln_states(target_id, vkey, state, comment, ip, "
                "port, title, cve_id, cvss, severity, detail, recommendation, "
                "tool, url, log_run_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target_id, vkey, state, comment or "", ip, port, title, cve_id,
                 cvss, severity, detail, recommendation, tool, url, log_run_id))
        c.commit()


def set_vuln_comment(target_id, vkey, comment):
    """Обновить только комментарий принятой уязвимости."""
    with _LOCK, connect() as c:
        c.execute(
            "UPDATE vuln_states SET comment=?, updated_at=datetime('now') "
            "WHERE target_id=? AND vkey=?", (comment or "", target_id, vkey))
        c.commit()


def clear_vuln_state(target_id, vkey):
    """Убрать состояние («отменить рассмотрение» / вернуть в обычный вид)."""
    with _LOCK, connect() as c:
        c.execute("DELETE FROM vuln_states WHERE target_id=? AND vkey=?",
                  (target_id, vkey))
        c.commit()


def list_vuln_states(target_id, state=None):
    """Список состояний объекта (опционально только accepted/hidden)."""
    q = "SELECT * FROM vuln_states WHERE target_id=?"
    args = [target_id]
    if state:
        q += " AND state=?"
        args.append(state)
    q += " ORDER BY updated_at DESC"
    with connect() as c:
        return [dict(r) for r in c.execute(q, args)]


def list_all_vuln_states(state=None):
    """П.11: список состояний по ВСЕМ объектам — для страницы «Разбор».

    Добавляет target_name и target_cidr через JOIN.
    """
    q = ("SELECT vs.*, t.name AS target_name, t.cidr AS target_cidr "
         "FROM vuln_states vs JOIN targets t ON t.id = vs.target_id")
    args = []
    if state:
        q += " WHERE vs.state=?"
        args.append(state)
    q += " ORDER BY vs.updated_at DESC"
    with connect() as c:
        return [dict(r) for r in c.execute(q, args)]


def count_accepted_vulns(target_id=None):
    """Число принятых в работу уязвимостей (для бейджа во вкладке)."""
    with connect() as c:
        if target_id is None:
            r = c.execute(
                "SELECT COUNT(*) AS n FROM vuln_states WHERE state='accepted'"
            ).fetchone()
        else:
            r = c.execute(
                "SELECT COUNT(*) AS n FROM vuln_states "
                "WHERE state='accepted' AND target_id=?", (target_id,)).fetchone()
    return int(r["n"]) if r else 0


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
