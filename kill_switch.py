"""
Kill Switch — always-on модель (v4, надёжная для OpenVPN GUI).

Что изменилось против старой версии и ПОЧЕМУ:

  Старая модель пускала наружу только VPN-сервер по IP:PORT и угадывала
  подсеть туннеля (localip=10.8.0.0/24). Это ломалось в двух частых случаях:
    1. .ovpn с именем сервера → DNS режется → VPN не коннектится → локаут.
    2. Реальная подсеть туннеля != угаданной → трафик внутри VPN режется.
  Плюс правило interfacetype=ras для OpenVPN бесполезно (TAP/Wintun не 'ras').

  Новая модель (надёжнее и проще в настройке):
    • Разрешаем сам процесс openvpn.exe ходить наружу (-Program). Тогда он
      сам решает DNS, коннектится к любому/failover серверу, переподключается —
      без ручного whitelist IP и без DNS-утечки (наружу ходит ТОЛЬКО openvpn.exe).
    • Разрешаем весь трафик на VPN-интерфейсе по ИМЕНИ адаптера (-InterfaceAlias),
      автодетект TAP-Windows/Wintun/OpenVPN. Не нужно угадывать подсеть.
    • Дефолтная исходящая политика = block. Всё, что не в whitelist, режется.

  Движок — PowerShell NetSecurity (New-/Remove-NetFirewallRule, Set-NetFirewallProfile):
    • Все правила в группе TunnelTrayKillSwitch → снос одной командой (быстро).
    • -Program и -InterfaceAlias недоступны в netsh advfirewall — поэтому PS.

  netsh оставлен только как аварийный сброс политики (см. emergency .bat).
"""

import ctypes
import socket
import subprocess
from pathlib import Path

CREATE_NO_WINDOW = 0x08000000

# Группа, которой помечаются ВСЕ наши firewall-правила. Снос: Remove-NetFirewallRule -Group ...
FIREWALL_GROUP = "TunnelTrayKillSwitch"

# Дефолтный путь к openvpn.exe (OpenVPN GUI кладёт сюда). Можно переопределить из конфига.
DEFAULT_OPENVPN_PATHS = [
    r"C:\Program Files\OpenVPN\bin\openvpn.exe",
    r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
]


# ============================================================
# Права администратора
# ============================================================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ============================================================
# Валидация IP
# ============================================================

def validate_ip(ip: str) -> bool:
    """Проверяет, что строка — валидный IPv4-адрес."""
    try:
        socket.inet_aton(ip)
        return ip.count('.') == 3
    except OSError:
        return False


# ============================================================
# Process-kill режим (tunnels_only, без админа)
# ============================================================

def kill_processes_by_name(process_names: list[str], logger=None) -> None:
    """Убивает процессы по имени. Используется в tunnels_only режиме."""
    for name in process_names:
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", name, "/T"],
                creationflags=CREATE_NO_WINDOW,
                capture_output=True, timeout=5, text=True,
                encoding="cp866", errors="replace",
            )
            if logger:
                if result.returncode == 0:
                    logger(f"[KILL] Процесс {name} убит")
                elif "128" not in (result.stderr or ""):
                    logger(f"[KILL] {name}: {result.stderr.strip() or 'не найден'}")
        except Exception as e:
            if logger:
                logger(f"[KILL ERROR] {name}: {e}")


# ============================================================
# PowerShell helper
# ============================================================

def _run_powershell(script: str, logger=None, timeout: int = 25) -> tuple[bool, str]:
    """Запускает PowerShell-скрипт скрыто. Возвращает (ok, output)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            creationflags=CREATE_NO_WINDOW,
            capture_output=True, timeout=timeout, text=True,
            encoding="utf-8", errors="replace",
        )
        out = (result.stdout or "") + (result.stderr or "")
        ok = result.returncode == 0
        if not ok and logger:
            logger(f"[FW ERROR] PowerShell rc={result.returncode}: {out.strip()[:500]}")
        return ok, out
    except Exception as e:
        if logger:
            logger(f"[FW EXCEPTION] {e}")
        return False, str(e)


def _ps_quote(s: str) -> str:
    """Безопасно оборачивает строку в одинарные кавычки для PowerShell."""
    return "'" + str(s).replace("'", "''") + "'"


# ============================================================
# Автодетект VPN-интерфейса и openvpn.exe
# ============================================================

def detect_vpn_interfaces(logger=None) -> list[str]:
    """
    Находит имена сетевых адаптеров OpenVPN/WireGuard (TAP-Windows / Wintun).
    Возвращает список Name (InterfaceAlias). Пусто — если не нашли.
    """
    script = (
        "Get-NetAdapter | Where-Object { "
        "$_.InterfaceDescription -match 'TAP-Windows|Wintun|OpenVPN|WireGuard' "
        "} | Select-Object -ExpandProperty Name"
    )
    ok, out = _run_powershell(script, logger=None)
    names = [line.strip() for line in out.splitlines() if line.strip()] if ok else []
    if logger:
        if names:
            logger(f"[FW] Найдены VPN-адаптеры: {names}")
        else:
            logger("[FW] VPN-адаптеры не найдены автодетектом "
                   "(TAP ещё не установлен/не поднят?) — использую fallback по подсети")
    return names


def detect_openvpn_exe(explicit: str | None = None) -> str | None:
    """Возвращает путь к openvpn.exe: явный из конфига или дефолтный существующий."""
    if explicit:
        return explicit  # доверяем пользователю, даже если файла нет в момент старта
    for p in DEFAULT_OPENVPN_PATHS:
        if Path(p).exists():
            return p
    return None


# ============================================================
# Политика firewall (default outbound)
# ============================================================

def _set_default_policy(block: bool, logger=None) -> bool:
    """
    block=True  → весь исходящий по умолчанию запрещён (входящий тоже).
    block=False → исходящий разрешён (восстановление дефолта Windows).
    """
    out_action = "Block" if block else "Allow"
    script = (
        f"Set-NetFirewallProfile -Profile Domain,Public,Private "
        f"-DefaultInboundAction Block -DefaultOutboundAction {out_action}"
    )
    ok, _ = _run_powershell(script, logger=logger)
    return ok


# ============================================================
# Cleanup
# ============================================================

def cleanup_firewall_rules(logger=None) -> None:
    """
    Удаляет ВСЕ наши правила (по группе, одной командой) и восстанавливает
    дефолтную исходящую политику (allow). Безопасно вызывать всегда.
    """
    _run_powershell(
        f"Remove-NetFirewallRule -Group {_ps_quote(FIREWALL_GROUP)} "
        f"-ErrorAction SilentlyContinue",
        logger=None,
    )
    _set_default_policy(block=False, logger=None)
    if logger:
        logger("[FW] Правила очищены (группа удалена), исходящая политика восстановлена (allow)")


def _add_rule(parts: list[str], logger=None) -> bool:
    """Собирает и выполняет New-NetFirewallRule. Группа и -Enabled добавляются всегда."""
    base = (
        f"New-NetFirewallRule -Group {_ps_quote(FIREWALL_GROUP)} "
        f"-Enabled True -ErrorAction Stop "
    )
    ok, _ = _run_powershell(base + " ".join(parts), logger=logger)
    return ok


# ============================================================
# Включение kill switch
# ============================================================

def enable_firewall_killswitch(
    vpn_server_ips: list[str],
    vpn_server_ports: list[int],
    vpn_protocols: list[str],
    allow_local_network: bool,
    inbound_allow: list[dict] | None,
    vpn_tunnel_subnet: str | None = None,
    openvpn_exe: str | None = None,
    vpn_interface_aliases: list[str] | None = None,
    logger=None,
) -> bool:
    """
    Включает always-on firewall kill switch (надёжная модель для OpenVPN GUI).

    Ключевые параметры:
      openvpn_exe: путь к openvpn.exe. Если задан/найден — разрешаем процессу
                   ходить наружу (DNS + коннект к любому серверу). Это убирает
                   зависимость от whitelist IP и предотвращает DNS-утечку.
      vpn_interface_aliases: имена VPN-адаптеров. None → автодетект. Разрешаем
                   весь трафик на этих интерфейсах — это трафик приложений
                   внутри туннеля (включая ssh-туннель из батника).

    Fallback (если openvpn_exe не найден / адаптер не задетектился):
      vpn_server_ips/ports/protocols — пускаем к VPN-серверу по IP:PORT.
      vpn_tunnel_subnet — пускаем исходящий с localip из подсети туннеля.
    """
    if not is_admin():
        if logger:
            logger("[FW ERROR] Требуются права администратора")
        return False

    cleanup_firewall_rules(logger=logger)

    # 1. Дефолтную исходящую политику → BLOCK.
    if not _set_default_policy(block=True, logger=logger):
        if logger:
            logger("[FW ERROR] Не удалось переключить политику в block — kill switch не включен")
        cleanup_firewall_rules(logger=logger)
        return False
    if logger:
        logger("[FW] Исходящая политика: BLOCK (всё, кроме allow-правил, заблокировано)")

    # 2. loopback — для локальных туннелей через 127.0.0.1
    _add_rule(["-DisplayName 'TT_AllowLoopback'", "-Direction Outbound", "-Action Allow",
               "-Profile Any", "-RemoteAddress 127.0.0.0/8"], logger=logger)

    # 3. DHCP — иначе после ребута сеть не получит IP
    _add_rule(["-DisplayName 'TT_AllowDHCP'", "-Direction Outbound", "-Action Allow",
               "-Profile Any", "-Protocol UDP", "-LocalPort 68", "-RemotePort 67"], logger=logger)

    # 4. ГЛАВНОЕ: разрешаем процессу openvpn.exe ходить наружу.
    #    Тогда он сам резолвит DNS и коннектится к любому/failover серверу.
    #    Наружу мимо VPN ходит ТОЛЬКО openvpn.exe — DNS-утечки нет.
    ovpn = detect_openvpn_exe(openvpn_exe)
    if ovpn:
        _add_rule(["-DisplayName 'TT_AllowOpenVPNProcess'", "-Direction Outbound",
                   "-Action Allow", "-Profile Any", f"-Program {_ps_quote(ovpn)}"], logger=logger)
        if logger:
            logger(f"[FW] Разрешён процесс OpenVPN наружу: {ovpn} (DNS+коннект к серверу)")
    else:
        if logger:
            logger("[FW WARN] openvpn.exe не найден — fallback на whitelist IP VPN-сервера. "
                   "Укажи путь в kill_switch.firewall.openvpn_exe для надёжности.")

    # 5. ГЛАВНОЕ-2: разрешаем весь трафик на VPN-интерфейсе по имени адаптера.
    #    Это трафик приложений ВНУТРИ туннеля (вкл. ssh-туннель из батника).
    aliases = vpn_interface_aliases if vpn_interface_aliases else detect_vpn_interfaces(logger=logger)
    if aliases:
        arr = ",".join(_ps_quote(a) for a in aliases)
        _add_rule(["-DisplayName 'TT_AllowVPNInterface'", "-Direction Outbound",
                   "-Action Allow", "-Profile Any", f"-InterfaceAlias {arr}"], logger=logger)
        if logger:
            logger(f"[FW] Разрешён весь исходящий на VPN-интерфейсах: {aliases}")
    elif vpn_tunnel_subnet:
        _add_rule(["-DisplayName 'TT_AllowVPNSubnet'", "-Direction Outbound",
                   "-Action Allow", "-Profile Any",
                   f"-LocalAddress {_ps_quote(vpn_tunnel_subnet)}"], logger=logger)
        if logger:
            logger(f"[FW] Fallback: разрешён исходящий из подсети туннеля {vpn_tunnel_subnet}")
    else:
        if logger:
            logger("[FW WARN] Не найден VPN-адаптер и не задана подсеть — "
                   "трафик внутри туннеля может быть заблокирован. "
                   "Подними VPN и перезапусти, либо укажи vpn_interface/vpn_tunnel_subnet.")

    # 6. Fallback-whitelist VPN-сервера по IP:PORT (belt-and-suspenders).
    valid_ips = [ip for ip in vpn_server_ips if validate_ip(ip)]
    if vpn_server_ips and not valid_ips and logger:
        logger("[FW WARN] В vpn_server_ips нет валидных IPv4 (DNS-имена не поддерживаются)")
    idx = 0
    for ip in valid_ips:
        for port in (vpn_server_ports or []):
            for proto in (vpn_protocols or ["udp"]):
                _add_rule([f"-DisplayName 'TT_AllowVPNServer_{idx}'", "-Direction Outbound",
                           "-Action Allow", "-Profile Any",
                           f"-RemoteAddress {_ps_quote(ip)}",
                           f"-RemotePort {int(port)}",
                           f"-Protocol {proto.upper()}"], logger=logger)
                idx += 1
    if valid_ips and logger:
        logger(f"[FW] Доп. whitelist VPN-серверов: {valid_ips} порты {vpn_server_ports}")

    # 7. Локальная сеть
    if allow_local_network:
        _add_rule(["-DisplayName 'TT_AllowLocalNet'", "-Direction Outbound", "-Action Allow",
                   "-Profile Any", "-RemoteAddress LocalSubnet"], logger=logger)
        if logger:
            logger("[FW] Разрешена локальная подсеть")

    # 8. Входящие правила в обход VPN (RDP, SSH-сервер и т.п.)
    if inbound_allow:
        for i, rule in enumerate(inbound_allow):
            if not rule.get("enabled", True):
                continue
            port = rule.get("port")
            if port is None:
                if logger:
                    logger(f"[FW WARN] inbound '{rule.get('name', i)}' без порта — пропуск")
                continue
            proto = rule.get("protocol", "tcp")
            parts = [f"-DisplayName 'TT_AllowInbound_{i}'", "-Direction Inbound",
                     "-Action Allow", "-Profile Any",
                     f"-Protocol {proto.upper()}", f"-LocalPort {int(port)}"]
            if rule.get("remoteip"):
                parts.append(f"-RemoteAddress {_ps_quote(rule['remoteip'])}")
            _add_rule(parts, logger=logger)
            if logger:
                logger(f"[FW] Разрешён входящий {proto.upper()}/{port} "
                       f"({rule.get('name', i)}, от {rule.get('remoteip', 'любой')})")

    if logger:
        logger("[FW] ✅ Kill switch АКТИВЕН (always-on)")
    return True


def disable_firewall_killswitch(logger=None) -> None:
    """Снимает kill switch: удаляет правила и восстанавливает дефолтную политику."""
    cleanup_firewall_rules(logger=logger)
    if logger:
        logger("[FW] ❌ Kill switch снят, исходящий трафик разрешён")
