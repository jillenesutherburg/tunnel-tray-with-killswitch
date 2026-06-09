"""
Kill Switch — always-on модель.

Логика (firewall режим):

Постоянно (пока программа работает):
  - Блокируется ВЕСЬ исходящий трафик.
  - Разрешается только трафик через VPN-интерфейс (interfacetype=ras).
  - Разрешается трафик к IP:PORT VPN-сервера (чтобы VPN мог установить/восстановить соединение).
  - Опционально: входящий трафик на указанный порт (например 3389 для RDP в обход VPN).
  - Опционально: локальная сеть (если включено).

В отличие от прошлой модели, kill switch активен ВСЕГДА пока работает программа.
Если VPN падает — ничего дополнительно делать не нужно, трафик уже заблокирован
(кроме VPN-сервера, через который VPN сможет переподключиться).

Режим tunnels_only оставлен для случаев когда нет прав админа: при падении VPN
убиваются все туннели + опционально указанные процессы.

Все firewall-правила маркируются группой FIREWALL_GROUP — это позволяет
найти и убрать их при следующем запуске, даже если программа упала.
"""

import ctypes
import socket
import subprocess
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000

# Группа, которой помечаются ВСЕ наши firewall-правила.
FIREWALL_GROUP = "TunnelTrayKillSwitch"


# ============================================================
# Проверка прав администратора
# ============================================================

def is_admin() -> bool:
    """Проверяет, запущен ли процесс с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ============================================================
# Резолвинг DNS-имён в IP
# ============================================================

def validate_ip(ip: str) -> bool:
    """Проверяет, что строка — валидный IPv4-адрес."""
    try:
        socket.inet_aton(ip)
        # inet_aton принимает '10' как '0.0.0.10', проверим количество точек
        return ip.count('.') == 3
    except OSError:
        return False


# ============================================================
# Process-kill режим (без админа)
# ============================================================

def kill_processes_by_name(process_names: list[str], logger=None) -> None:
    """Убивает процессы по имени. Используется в tunnels_only режиме."""
    for name in process_names:
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", name, "/T"],
                creationflags=CREATE_NO_WINDOW,
                capture_output=True,
                timeout=5,
                text=True,
            )
            if logger:
                if result.returncode == 0:
                    logger(f"[KILL] Процесс {name} убит")
                else:
                    if "128" not in (result.stderr or ""):
                        logger(f"[KILL] {name}: {result.stderr.strip() or 'не найден'}")
        except Exception as e:
            if logger:
                logger(f"[KILL ERROR] {name}: {e}")


# ============================================================
# Firewall kill switch (always-on, требует админа)
# ============================================================

def _run_netsh(args: list[str], logger=None) -> tuple[bool, str]:
    """Запускает netsh advfirewall."""
    cmd = ["netsh", "advfirewall"] + args
    try:
        result = subprocess.run(
            cmd,
            creationflags=CREATE_NO_WINDOW,
            capture_output=True,
            timeout=10,
            text=True,
            encoding="cp866",
            errors="replace",
        )
        ok = result.returncode == 0
        output = (result.stdout or "") + (result.stderr or "")
        if not ok and logger:
            logger(f"[FW ERROR] {' '.join(cmd)} → {output.strip()}")
        return ok, output
    except Exception as e:
        if logger:
            logger(f"[FW EXCEPTION] {e}")
        return False, str(e)


def _rule_name(suffix: str) -> str:
    return f"{FIREWALL_GROUP}_{suffix}"


# Заранее известные имена правил — для cleanup
_KNOWN_RULE_SUFFIXES = [
    "BlockAllOut",
    "AllowVPNInterface",
    "AllowLocalNetOut",
    "AllowDHCP",
    "AllowLoopback",
]


def cleanup_firewall_rules(logger=None) -> None:
    """
    Удаляет все правила нашей группы. Безопасно вызывать всегда.
    Чистит также правила с индексами (AllowVPNServer_N, AllowInbound_N).
    """
    for suffix in _KNOWN_RULE_SUFFIXES:
        _run_netsh(
            ["firewall", "delete", "rule", f"name={_rule_name(suffix)}"],
            logger=None,
        )
    # Правила с индексами — с запасом
    for prefix in ("AllowVPNServer_", "AllowInbound_"):
        for i in range(50):
            _run_netsh(
                ["firewall", "delete", "rule", f"name={_rule_name(f'{prefix}{i}')}"],
                logger=None,
            )
    # Старое имя на всякий случай (для миграции с прошлой версии)
    _run_netsh(
        ["firewall", "delete", "rule", f"name={_rule_name('AllowRDPIn')}"],
        logger=None,
    )
    if logger:
        logger(f"[FW] Старые правила группы '{FIREWALL_GROUP}' очищены")


def enable_firewall_killswitch(
    vpn_server_ips: list[str],
    vpn_server_ports: list[int],
    vpn_protocols: list[str],
    allow_local_network: bool,
    inbound_allow: list[dict] | None,
    logger=None,
) -> bool:
    """
    Включает always-on firewall kill switch.

    Параметры:
      vpn_server_ips: список IPv4-адресов VPN-серверов (НЕ DNS-имена).
      vpn_server_ports: список портов.
      vpn_protocols: ["udp"], ["tcp"], или оба.
      allow_local_network: разрешить локальную подсеть.
      inbound_allow: список словарей вида {"port": 3389, "protocol": "tcp", "name": "RDP"}
                     для разрешения входящих коннектов в обход VPN.
    """
    if not is_admin():
        if logger:
            logger("[FW ERROR] Требуются права администратора")
        return False

    # Валидируем IP-адреса
    valid_ips = []
    for ip in vpn_server_ips:
        if validate_ip(ip):
            valid_ips.append(ip)
        elif logger:
            logger(f"[FW ERROR] '{ip}' не похож на IPv4-адрес — пропускаем. "
                   f"DNS-имена не поддерживаются, используй прямой IP")

    if not valid_ips:
        if logger:
            logger("[FW ERROR] Нет ни одного валидного IP VPN-сервера, kill switch не включен")
        return False

    cleanup_firewall_rules(logger=logger)

    if logger:
        logger(f"[FW] VPN-серверы: {valid_ips}")

    # 1. БЛОК всего исходящего
    ok, _ = _run_netsh([
        "firewall", "add", "rule",
        f"name={_rule_name('BlockAllOut')}",
        f"group={FIREWALL_GROUP}",
        "dir=out",
        "action=block",
        "enable=yes",
        "profile=any",
    ], logger=logger)
    if not ok:
        cleanup_firewall_rules(logger=logger)
        return False

    # 2. РАЗРЕШИТЬ loopback (127.0.0.0/8) — для локальных туннелей
    _run_netsh([
        "firewall", "add", "rule",
        f"name={_rule_name('AllowLoopback')}",
        f"group={FIREWALL_GROUP}",
        "dir=out",
        "action=allow",
        "enable=yes",
        "profile=any",
        "remoteip=127.0.0.0/8",
    ], logger=logger)

    # 3. РАЗРЕШИТЬ DHCP — иначе сеть не получит IP после ребута
    _run_netsh([
        "firewall", "add", "rule",
        f"name={_rule_name('AllowDHCP')}",
        f"group={FIREWALL_GROUP}",
        "dir=out",
        "action=allow",
        "enable=yes",
        "profile=any",
        "protocol=udp",
        "localport=68",
        "remoteport=67",
    ], logger=logger)

    # 4. РАЗРЕШИТЬ VPN-интерфейс (весь трафик через ras-интерфейсы)
    _run_netsh([
        "firewall", "add", "rule",
        f"name={_rule_name('AllowVPNInterface')}",
        f"group={FIREWALL_GROUP}",
        "dir=out",
        "action=allow",
        "enable=yes",
        "profile=any",
        "interfacetype=ras",
    ], logger=logger)
    if logger:
        logger("[FW] Разрешён трафик через VPN-интерфейсы (type=ras)")

    # 5. РАЗРЕШИТЬ коннект к IP:PORT VPN-сервера
    rule_idx = 0
    for ip in valid_ips:
        for port in vpn_server_ports:
            for proto in vpn_protocols:
                _run_netsh([
                    "firewall", "add", "rule",
                    f"name={_rule_name(f'AllowVPNServer_{rule_idx}')}",
                    f"group={FIREWALL_GROUP}",
                    "dir=out",
                    "action=allow",
                    "enable=yes",
                    "profile=any",
                    f"remoteip={ip}",
                    f"remoteport={port}",
                    f"protocol={proto}",
                ], logger=logger)
                rule_idx += 1
    if logger:
        logger(f"[FW] Разрешён коннект к {len(valid_ips)} IP VPN-серверов "
               f"на портах {vpn_server_ports} ({'/'.join(vpn_protocols)})")

    # 6. Локальная сеть
    if allow_local_network:
        _run_netsh([
            "firewall", "add", "rule",
            f"name={_rule_name('AllowLocalNetOut')}",
            f"group={FIREWALL_GROUP}",
            "dir=out",
            "action=allow",
            "enable=yes",
            "profile=any",
            "remoteip=LocalSubnet",
        ], logger=logger)
        if logger:
            logger("[FW] Разрешена локальная подсеть")

    # 7. Входящие правила в обход VPN (RDP и другие сервисы)
    if inbound_allow:
        for idx, rule in enumerate(inbound_allow):
            if not rule.get("enabled", True):
                continue
            port = rule.get("port")
            proto = rule.get("protocol", "tcp")
            rule_label = rule.get("name", f"Inbound_{idx}")

            if port is None:
                if logger:
                    logger(f"[FW WARN] Inbound rule '{rule_label}' без порта — пропуск")
                continue

            # remoteip — опциональный whitelist источников
            cmd = [
                "firewall", "add", "rule",
                f"name={_rule_name(f'AllowInbound_{idx}')}",
                f"group={FIREWALL_GROUP}",
                "dir=in",
                "action=allow",
                "enable=yes",
                "profile=any",
                f"protocol={proto}",
                f"localport={port}",
            ]
            if "remoteip" in rule:
                cmd.append(f"remoteip={rule['remoteip']}")

            _run_netsh(cmd, logger=logger)
            if logger:
                src = rule.get("remoteip", "любой источник")
                logger(f"[FW] Разрешён входящий {proto.upper()} порт {port} "
                       f"({rule_label}, от: {src})")

    if logger:
        logger("[FW] ✅ Kill switch АКТИВЕН (always-on)")
    return True


def disable_firewall_killswitch(logger=None) -> None:
    """Отключает kill switch — снимает все наши правила."""
    cleanup_firewall_rules(logger=logger)
    if logger:
        logger("[FW] ❌ Kill switch снят")
