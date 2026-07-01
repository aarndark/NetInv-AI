"""Коллектор ошибок и статусов модулей сканирования (NetInv v1.6.0, треб. 2, 3).

Собирает ОЧЕВИДНЫЕ ошибки инструментов (недоступность онлайн-CVE БД, HTTP 400
OSV, сбои парсинга и т.п.) и статусы модулей с учётом graceful degradation.
Информация о РЕЗУЛЬТАТАХ скана (недоступность хостов, отсутствие открытых
портов и пр.) СЮДА НЕ ПОПАДАЕТ — только ошибки самих инструментов.

Особенность: часть решений graceful degradation (отключение vulners,
недоступность OSV, отсутствие DNS-утилит) принимается ДО создания записи о
запуске (run_id ещё нет). Поэтому sink буферизует всё в памяти и сбрасывает в
БД (`flush`) сразу после того, как run_id становится известен.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402


# --- Человекочитаемые названия модулей для UI (треб. 3) --------------------
MODULE_LABELS = {
    "nmap": "nmap",
    "nse": "nmap NSE",
    "nse_vulners": "nmap NSE vulners",
    "whatweb": "WhatWeb",
    "nikto": "Nikto",
    "wpscan": "WPScan",
    "dalfox": "Dalfox",
    "cve_online": "Онлайн-CVE (OSV/NVD)",
    "cve_offline": "Offline-таблица CVE",
    "osv": "OSV (api.osv.dev)",
    "dns_recon": "DNS-разведка",
    "dns_brute": "DNS brute-force",
    "dig_rdns": "Обратный DNS (dig -x)",
    "webscan": "Web-сканер",
    "parse": "Парсер результатов",
}

# Статусы модуля (треб. 2).
STATUS_USED = "used"                    # применён успешно
STATUS_SKIPPED_MISSING = "skipped_missing"    # пропущен: нет бинарника/утилиты
STATUS_SKIPPED_DEGRADED = "skipped_degraded"  # деградация: недоступен сервис и т.п.
STATUS_OFF = "off"                      # выключен опциями запуска


# Регэкспы для перехвата ОШИБОК из строк лога (те, что уже пишутся в консоль/
# файл через callback log). Пойманные строки дублируются в scan_errors.
# Каждый элемент: (module, kind, compiled_regex).
_LOG_ERROR_PATTERNS = [
    # OSV HTTP 400 для <продукт> (без версии) — пропускаю (используется offline)
    ("osv", "error", re.compile(r"OSV HTTP \d+ для .+пропускаю", re.I)),
    # OSV недоступен для <продукт>: <urlopen error ...> (используется offline)
    ("osv", "error", re.compile(r"OSV недоступен для .+", re.I)),
    # OSV НЕДОСТУПЕН<proxy>: <ошибка> (из osv_healthcheck)
    ("osv", "error", re.compile(r"OSV НЕДОСТУПЕН.*:", re.I)),
    # Ошибка парсинга XML nmap
    ("parse", "error", re.compile(r"Ошибка парсинга XML", re.I)),
    # assess_vulns(<url>) ошибка: <исключение>
    ("webscan", "error", re.compile(r"assess_vulns\(.+\) ошибка", re.I)),
]


class ErrorSink:
    """Буфер ошибок и статусов модулей с отложенной записью в БД."""

    def __init__(self):
        self.run_id = None
        self._errors = []    # список dict: module/kind/message/detail
        self._modules = {}   # module -> dict: status/reason (последний побеждает)
        self._seen_err = set()  # дедупликация (module, message)

    # --- запись ошибок -----------------------------------------------------
    def error(self, module, message, detail=None, kind="error"):
        """Зафиксировать ОЧЕВИДНУЮ ошибку инструмента (треб. 3)."""
        key = (module, kind, message)
        if key in self._seen_err:
            return
        self._seen_err.add(key)
        rec = {"module": module, "kind": kind, "message": message, "detail": detail}
        self._errors.append(rec)
        if self.run_id is not None:
            db.add_scan_error(self.run_id, module, message, detail, kind)

    def degraded(self, module, message, detail=None):
        """Инфо о graceful degradation (модуль не применялся) — как «мягкая»
        запись в колонке ошибок (kind='degraded')."""
        self.error(module, message, detail=detail, kind="degraded")

    # --- перехват из лога --------------------------------------------------
    def scan_log_line(self, line):
        """Проверить строку лога на известные шаблоны ошибок инструментов и,
        при совпадении, продублировать её в scan_errors. Возвращает True, если
        строка распознана как ошибка (для тестов)."""
        text = str(line)
        for module, kind, rx in _LOG_ERROR_PATTERNS:
            if rx.search(text):
                # Уберём префикс "[cve] " / "[dns] " для аккуратного сообщения.
                msg = re.sub(r"^\[[a-z]+\]\s*", "", text).strip()
                self.error(module, msg, kind=kind)
                return True
        return False

    # --- статусы модулей ---------------------------------------------------
    def module(self, module, status=STATUS_USED, reason=None):
        """Зафиксировать статус модуля (треб. 2). Повторный вызов обновляет."""
        self._modules[module] = {"status": status, "reason": reason}
        if self.run_id is not None:
            db.set_scan_module(self.run_id, module, status, reason)

    # --- привязка к запуску и сброс в БД -----------------------------------
    def bind_run(self, run_id):
        """Привязать sink к созданному запуску и сбросить буфер в БД."""
        self.run_id = run_id
        self.flush()

    def flush(self):
        """Записать накопленные ошибки и статусы модулей в БД."""
        if self.run_id is None:
            return
        for e in self._errors:
            db.add_scan_error(self.run_id, e["module"], e["message"],
                              e["detail"], e["kind"])
        for module, m in self._modules.items():
            db.set_scan_module(self.run_id, module, m["status"], m["reason"])
        # После сброса очищаем буфер, чтобы избежать двойной записи, если flush
        # будет вызван повторно (последующие вызовы пишут напрямую в БД).
        self._errors = []

    # --- сериализация модулей для scan_runs.modules_json (треб. 2) ---------
    def modules_json(self):
        """JSON-список модулей и их статусов для быстрого рендера."""
        out = [{"module": m, "label": MODULE_LABELS.get(m, m),
                "status": v["status"], "reason": v["reason"]}
               for m, v in sorted(self._modules.items())]
        return json.dumps(out, ensure_ascii=False)
