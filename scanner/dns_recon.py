"""
Модуль DNS-разведки для NetInv.

Назначение
----------
Привязка доменных имён к объекту сканирования. Логика:

  * Домен второго уровня (например ``domainname.ru`` — две метки) —
    проводим поиск поддоменов утилитами ``dnsmap``, ``dnsenum``,
    ``dnsrecon`` и резолвим найденные имена в IP-адреса.
  * Домен третьего и ниже уровней (например ``host1.domainname.ru`` —
    три и более меток) — поиск поддоменов не нужен, просто резолвим
    IP-адрес и добавляем его к сканированию.

Все внешние утилиты вызываются с проверкой наличия (``shutil.which``)
и тайм-аутами. Если утилита не установлена — модуль корректно
деградирует (пропускает её, пишет предупреждение), не прерывая скан.

Возвращаемые структуры
----------------------
``recon_domain(...)`` возвращает словарь:

    {
        "domain":       исходный домен,
        "level":        2 | 3+ (число меток),
        "is_apex":      True для домена второго уровня,
        "ips":          {ip: source}     # source: 'domain' | 'subdomain'
        "subdomains":   [ {parent, subdomain, ip, tool}, ... ],
        "fqdn_by_ip":   {ip: fqdn}        # для обогащения "Доменное имя"
        "tools_used":   [список доступных утилит],
        "tools_missing":[список отсутствующих утилит],
    }
"""

import os
import re
import shutil
import socket
import subprocess

# ----------------------- константы -----------------------

# Тайм-ауты (сек) для внешних утилит. Поддомен-брутфорс может быть
# долгим, поэтому даём ему отдельный, больший тайм-аут.
RESOLVE_TIMEOUT = 8        # dig +short / резолв одиночного имени
RECON_TIMEOUT = 240        # dnsmap/dnsenum/dnsrecon в обычном режиме
RECON_TIMEOUT_BRUTE = 600  # тот же набор при включённом brute-force

# Регулярные выражения для разбора вывода утилит.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Имя хоста (FQDN): метки из букв/цифр/дефисов, минимум одна точка.
_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}\b")


# ----------------------- утилиты уровня домена -----------------------

def domain_level(domain):
    """Число меток в домене (host1.example.ru -> 3, example.ru -> 2)."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return 0
    return len([p for p in domain.split(".") if p])


def is_apex_domain(domain):
    """True, если домен второго уровня (apex) — требует поиска поддоменов."""
    return domain_level(domain) == 2


def domain_sort_key(domain):
    """Ключ ИЕРАРХИЧЕСКОЙ сортировки доменов (требование 3 v1.5.0).

    Каждый домен идёт ВМЕСТЕ со своими поддоменами сразу под ним
    (родитель -> его дети -> следующий родитель), а НЕ «все 2-е уровни,
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
    родителя группируются вместе.

    Применять как key= в sorted().
    """
    norm = (domain or "").strip().lower().rstrip(".")
    labels = [p for p in norm.split(".") if p]
    # Метки справа налево: TLD первым -> иерархическая группировка
    # родитель->дети. Без отдельного «уровня» в ключе.
    return tuple(reversed(labels))


# ----------------------- резолв имён -----------------------

def resolve_host(name, timeout=RESOLVE_TIMEOUT):
    """Прямой резолв имени в список IPv4. Сначала ``dig``, иначе socket.

    Возвращает отсортированный список уникальных IP-адресов (может быть
    пустым, если имя не резолвится).
    """
    name = (name or "").strip().rstrip(".")
    if not name:
        return []
    ips = set()

    dig = shutil.which("dig")
    if dig:
        try:
            out = subprocess.run(
                [dig, "+short", "A", name],
                capture_output=True, text=True, timeout=timeout)
            for line in out.stdout.splitlines():
                line = line.strip()
                if _IPV4_RE.fullmatch(line):
                    ips.add(line)
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Резервный путь — системный резолвер.
    if not ips:
        try:
            for res in socket.getaddrinfo(name, None, socket.AF_INET):
                ips.add(res[4][0])
        except (socket.gaierror, OSError):
            pass

    return sorted(ips)


# ----------------------- разбор вывода утилит -----------------------

def _extract_pairs(text, parent):
    """Извлечь пары (поддомен, ip) из произвольного текстового вывода.

    Логика построчная: если в строке есть имя, относящееся к ``parent``,
    и в этой же строке есть IP — связываем их. Имена без IP сохраняем для
    последующего отдельного резолва.
    """
    parent = (parent or "").strip().lower().rstrip(".")
    pairs = []          # (subdomain, ip)
    names_only = set()  # поддомены без IP в этой же строке

    for line in text.splitlines():
        low = line.lower()
        hosts = [h.rstrip(".").lower() for h in _HOST_RE.findall(low)
                 if h.rstrip(".").lower().endswith("." + parent)
                 or h.rstrip(".").lower() == parent]
        ips = _IPV4_RE.findall(line)
        if hosts and ips:
            for h in hosts:
                for ip in ips:
                    pairs.append((h, ip))
        elif hosts:
            for h in hosts:
                names_only.add(h)

    # Имена, для которых IP так и не нашёлся в выводе.
    paired_names = {p[0] for p in pairs}
    leftover = names_only - paired_names
    return pairs, leftover


# ----------------------- запуск конкретных утилит -----------------------

def _run_dnsmap(domain, brute, timeout):
    """dnsmap — поиск поддоменов перебором по встроенному словарю."""
    pairs, leftover = [], set()
    cmd = ["dnsmap", domain]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        p, lo = _extract_pairs(out.stdout + "\n" + out.stderr, domain)
        pairs.extend(p)
        leftover |= lo
    except (subprocess.TimeoutExpired, OSError):
        pass
    return pairs, leftover


def _run_dnsenum(domain, brute, timeout):
    """dnsenum — комплексная разведка DNS (NS, MX, перебор поддоменов)."""
    pairs, leftover = [], set()
    # --noreverse ускоряет; перебор словарём оставляем по умолчанию.
    cmd = ["dnsenum", "--noreverse", domain]
    if not brute:
        # Быстрый/пассивный режим: без рекурсивного перебора словарём.
        cmd = ["dnsenum", "--noreverse", "--enum", domain]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        p, lo = _extract_pairs(out.stdout + "\n" + out.stderr, domain)
        pairs.extend(p)
        leftover |= lo
    except (subprocess.TimeoutExpired, OSError):
        pass
    return pairs, leftover


def _run_dnsrecon(domain, brute, timeout):
    """dnsrecon — стандартная разведка, при brute=True добавляем перебор."""
    pairs, leftover = [], set()
    # -t std: стандартные записи (A, NS, MX, SOA, SRV).
    types = "std"
    if brute:
        # Добавляем перебор поддоменов словарём (brute-force).
        types = "std,brt"
    cmd = ["dnsrecon", "-d", domain, "-t", types]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        p, lo = _extract_pairs(out.stdout + "\n" + out.stderr, domain)
        pairs.extend(p)
        leftover |= lo
    except (subprocess.TimeoutExpired, OSError):
        pass
    return pairs, leftover


_TOOLS = {
    "dnsmap": _run_dnsmap,
    "dnsenum": _run_dnsenum,
    "dnsrecon": _run_dnsrecon,
}


# ----------------------- разведка поддоменов apex-домена -----------------------

def discover_subdomains(domain, brute=False, log=None):
    """Поиск поддоменов apex-домена доступными утилитами.

    Параметры:
        domain — домен второго уровня (apex).
        brute  — включить brute-force перебор словарём (медленнее, полнее).
        log    — необязательная функция логирования (например print).

    Возвращает: (subdomains, tools_used, tools_missing)
        где subdomains — список dict {parent, subdomain, ip, tool}.
    """
    def _log(msg):
        if log:
            log(msg)

    domain = (domain or "").strip().lower().rstrip(".")
    timeout = RECON_TIMEOUT_BRUTE if brute else RECON_TIMEOUT

    found = {}   # (subdomain, ip) -> tool ; ip может быть None
    tools_used, tools_missing = [], []

    for tool_name, runner in _TOOLS.items():
        if not shutil.which(tool_name):
            tools_missing.append(tool_name)
            _log(f"[dns_recon] утилита {tool_name} не найдена — пропуск")
            continue
        tools_used.append(tool_name)
        mode = "brute-force" if brute else "обычный"
        _log(f"[dns_recon] {tool_name}: разведка {domain} ({mode} режим)")
        pairs, leftover = runner(domain, brute, timeout)
        for sub, ip in pairs:
            key = (sub, ip)
            found.setdefault(key, tool_name)
        # Имена без IP — резолвим отдельно, чтобы добавить их к сканированию.
        for sub in leftover:
            resolved = resolve_host(sub)
            if resolved:
                for ip in resolved:
                    found.setdefault((sub, ip), tool_name)
            else:
                # Имя найдено, но не резолвится — сохраняем без IP.
                found.setdefault((sub, None), tool_name)

    subdomains = [
        {"parent": domain, "subdomain": sub, "ip": ip, "tool": tool}
        for (sub, ip), tool in sorted(found.items(),
                                      key=lambda kv: (kv[0][0], kv[0][1] or ""))
    ]
    return subdomains, tools_used, tools_missing


# ----------------------- основная точка входа -----------------------

def recon_domain(domain, brute=False, log=None):
    """Полная обработка одного домена объекта сканирования.

    * apex-домен (2 метки)  -> поиск поддоменов + резолв.
    * поддомен (3+ меток)   -> только резолв IP.

    Возвращает структуру, описанную в docstring модуля.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    level = domain_level(domain)
    apex = level == 2

    result = {
        "domain": domain,
        "level": level,
        "is_apex": apex,
        "ips": {},          # ip -> source ('domain' | 'subdomain')
        "subdomains": [],   # [{parent, subdomain, ip, tool}]
        "fqdn_by_ip": {},   # ip -> fqdn (для поля "Доменное имя")
        "tools_used": [],
        "tools_missing": [],
    }

    if not domain or level < 2:
        return result

    # Сам домен всегда резолвим и добавляем как источник 'domain'.
    for ip in resolve_host(domain):
        result["ips"][ip] = "domain"
        result["fqdn_by_ip"].setdefault(ip, domain)

    if apex:
        subs, used, missing = discover_subdomains(domain, brute=brute, log=log)
        result["tools_used"] = used
        result["tools_missing"] = missing
        for s in subs:
            result["subdomains"].append(s)
            ip = s.get("ip")
            if ip:
                # Поддомены, найденные разведкой, имеют источник 'subdomain'.
                result["ips"].setdefault(ip, "subdomain")
                result["fqdn_by_ip"].setdefault(ip, s["subdomain"])
    else:
        # Домен третьего+ уровня — это и есть «поддомен», только резолвим.
        # Родитель — домен на уровень выше.
        parent = ".".join(domain.split(".")[1:])
        for ip in resolve_host(domain):
            result["subdomains"].append({
                "parent": parent, "subdomain": domain,
                "ip": ip, "tool": "resolve",
            })

    return result
