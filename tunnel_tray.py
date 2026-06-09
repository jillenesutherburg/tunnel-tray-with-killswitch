"""
Tunnel Tray Manager v3
=======================
Программа для управления .bat файлами туннелей через системный трей Windows.

Новое в v3:
  - Single-instance защита (именованный mutex)
  - Валидация конфига при старте (дубликаты имён, битые depends_on, циклы)
  - Защита от случайной блокировки интернета: kill switch не включается
    если в vpn_server_ips остался плейсхолдер
  - Гарантия что cleanup_firewall_rules выполняется ТОЛЬКО при KS enabled
  - Корректное завершение монитор-потоков (join при disable, перед re-enable)
  - Исправлена утечка _log_file при сбое Popen
  - Ротация логов туннелей (>5 МБ → оставляем последние 2 МБ)
  - Debounce уведомлений (одно и то же не чаще раза в 60 сек)
  - Backoff расширен: 5 → 10 → 30 → 60 → 120 сек

Зависимости: pystray, pillow
Запуск:      pythonw tunnel_tray.py
Сборка exe:  pyinstaller --noconsole --onefile --icon=app.ico tunnel_tray.py
"""

import atexit
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
import winreg
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import pystray
from PIL import Image, ImageDraw, ImageFont

import kill_switch


# ============================================================
# Пути
# ============================================================

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).parent
else:
    APP_DIR = Path(__file__).parent

CONFIG_PATH = APP_DIR / "tunnels.json"
LOGS_DIR = APP_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

APP_NAME = "TunnelTrayManager"

# Флаги для скрытого запуска подпроцессов
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200

# Маркер дефолтного IP в шаблоне конфига. Используется чтобы отказать
# во включении firewall kill switch если пользователь не поменял плейсхолдер
# (защита от того что человек случайно заблокирует себе интернет).
PLACEHOLDER_VPN_IP = "1.2.3.4"

# Ротация логов туннелей
LOG_MAX_SIZE = 5 * 1024 * 1024   # 5 МБ — порог срабатывания
LOG_KEEP_SIZE = 2 * 1024 * 1024  # 2 МБ — что оставляем после ротации

# Debounce уведомлений в трее
NOTIFICATION_DEBOUNCE_SEC = 60


# ============================================================
# Single-instance защита
# ============================================================
# Именованный mutex Win32. Если другой инстанс уже работает —
# второй запуск тихо завершается, не плодя дубликаты иконок в трее.

MUTEX_NAME = "Global\\TunnelTrayManager_SingleInstance_v1"
ERROR_ALREADY_EXISTS = 183


def acquire_single_instance():
    """
    Захватывает именованный mutex. Возвращает handle или None если занят.
    Handle нужно держать живым на всё время работы программы.
    """
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return None
        return handle
    except Exception:
        # Если что-то пошло не так с WinAPI — лучше дать программе запуститься,
        # чем не запустить из-за защиты от двойного запуска
        return -1


# ============================================================
# JSONC — JSON с комментариями
# ============================================================
# tunnels.json поддерживает однострочные // комментарии.
# Перед парсингом они вырезаются с учётом строковых литералов
# (чтобы "https://..." внутри значений не пострадало).

def strip_json_comments(text: str) -> str:
    """Удаляет // комментарии из JSONC, не трогая содержимое строк."""
    result = []
    i = 0
    in_string = False
    escape_next = False
    while i < len(text):
        c = text[i]
        if escape_next:
            result.append(c)
            escape_next = False
            i += 1
            continue
        if c == '\\' and in_string:
            result.append(c)
            escape_next = True
            i += 1
            continue
        if c == '"':
            in_string = not in_string
            result.append(c)
            i += 1
            continue
        if not in_string and c == '/' and i + 1 < len(text) and text[i + 1] == '/':
            # Пропускаем всё до конца строки
            while i < len(text) and text[i] != '\n':
                i += 1
            continue
        result.append(c)
        i += 1
    return ''.join(result)


# ============================================================
# Статусы туннеля
# ============================================================

class Status(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    WAITING_DEP = "waiting_dep"
    RECONNECTING = "reconnecting"


# ============================================================
# Конфиг
# ============================================================

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        example = {
            "kill_switch": {
                "enabled": False,
                "mode": "tunnels_only",
                "_mode_help": "tunnels_only — без админа, рубит туннели и процессы при падении VPN. firewall — настоящий always-on kill switch (весь трафик идёт только через VPN), нужен админ.",
                "vpn_tunnel": "openvpn",
                "_vpn_tunnel_help": "Имя туннеля из 'tunnels' который считается VPN. В tunnels_only режиме — при его падении срабатывает kill switch. В firewall режиме — нужен только для статусной индикации в трее.",
                "kill_processes": [],
                "_kill_processes_help": "Только для tunnels_only: список .exe для taskkill при падении VPN. Например: [\"chrome.exe\"]",
                "firewall": {
                    "_help": "Always-on kill switch. Активируется при старте программы. Весь трафик идёт ТОЛЬКО через VPN-интерфейс. В обход разрешён только сам процесс openvpn.exe (для коннекта к серверу) + loopback/DHCP/локалка.",
                    "openvpn_exe": "C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
                    "_openvpn_exe_help": "Путь к openvpn.exe. Этому процессу разрешается ходить наружу — он сам резолвит DNS и коннектится к серверу (в т.ч. failover). Это надёжнее whitelist по IP и убирает DNS-утечку. Если оставить пустым — программа поищет в стандартных местах.",
                    "vpn_interface": None,
                    "_vpn_interface_help": "Имя сетевого адаптера OpenVPN (например 'OpenVPN TAP-Windows6'). Весь трафик на нём разрешается — это трафик приложений ВНУТРИ туннеля. null = автодетект (ищет TAP-Windows/Wintun). Узнать имя: PowerShell 'Get-NetAdapter'. Если автодетект не сработал — впиши имя сюда.",
                    "vpn_server_ips": [],
                    "_vpn_server_ips_help": "НЕОБЯЗАТЕЛЬНО при заданном openvpn_exe (он сам коннектится). Это запасной whitelist VPN-сервера по IP. Только IPv4 (НЕ DNS-имена). Узнать: nslookup vpn.example.com.",
                    "vpn_server_ports": [1194],
                    "_vpn_server_ports_help": "Порты VPN-сервера (для запасного whitelist). 1194 (OpenVPN), 51820 (WireGuard), 443.",
                    "vpn_protocols": ["udp"],
                    "_vpn_protocols_help": "Протоколы запасного whitelist: [\"udp\"], [\"tcp\"], или оба.",
                    "vpn_tunnel_subnet": "10.8.0.0/24",
                    "_vpn_tunnel_subnet_help": "Запасной вариант, если vpn_interface не задан и адаптер не задетектился. Подсеть туннеля. Обычно у OpenVPN 10.8.0.0/24. Лучше задать vpn_interface — надёжнее.",
                    "allow_local_network": True,
                    "_allow_local_network_help": "Разрешать локальную подсеть (для NAS, принтеров, RDP в локалке).",
                    "cleanup_on_exit": False,
                    "_cleanup_on_exit_help": "false (по умолчанию) — правила остаются в firewall даже после выхода. Параноидальная модель: не утечёт даже если прога выключена. Аварийно снять: запусти 'ОТКЛЮЧИТЬ-killswitch.bat' от админа. true — выход из программы разблокирует интернет.",
                    "inbound_allow": [
                        {
                            "enabled": False,
                            "name": "RDP",
                            "port": 3389,
                            "protocol": "tcp",
                            "_help": "Разрешить входящий RDP в обход VPN. Опционально 'remoteip': '192.168.1.0/24' — только из локалки."
                        }
                    ],
                    "_inbound_allow_help": "Список разрешённых входящих правил. Каждое: {name, port, protocol, enabled, опционально remoteip}. Например, можно добавить SSH (22/tcp), web-сервер (80,443/tcp) и т.д."
                }
            },
            "tunnels": [
                {
                    "name": "openvpn",
                    "_name_help": "Любое короткое имя. На него ссылается depends_on у других туннелей.",
                    "monitor_only": True,
                    "_monitor_only_help": "true — программа НЕ запускает .bat, а только следит жив ли VPN (для случая когда VPN поднимается внешним клиентом, напр. OpenVPN GUI). Зависимые туннели стартуют когда этот станет HEALTHY. false (или убрать) — программа сама запускает bat_path.",
                    "bat_path": None,
                    "autostart": True,
                    "depends_on": None,
                    "health_check": {
                        "type": "openvpn",
                        "process": "openvpn.exe",
                        "_process_help": "Имя процесса OpenVPN. VPN считается живым только если процесс запущен.",
                        "host": "10.8.0.1",
                        "_host_help": "IP внутри VPN-сети (шлюз туннеля) для проверки что туннель реально жив. Узнать после коннекта: ipconfig → адаптер TAP/TUN. Если оставить null — проверяется только наличие процесса.",
                        "interval_sec": 15,
                        "timeout_sec": 3,
                        "initial_delay_sec": 10
                    },
                    "auto_reconnect": True
                },
                {
                    "name": "ssh_db",
                    "bat_path": "C:\\tunnels\\ssh_db.bat",
                    "autostart": True,
                    "depends_on": "openvpn",
                    "health_check": {
                        "type": "tcp",
                        "host": "127.0.0.1",
                        "ports": [5432, 5433],
                        "interval_sec": 10,
                        "timeout_sec": 2,
                        "initial_delay_sec": 5
                    },
                    "auto_reconnect": True
                },
                {
                    "name": "standalone",
                    "bat_path": "C:\\tunnels\\standalone.bat",
                    "autostart": False,
                    "depends_on": None,
                    "health_check": {
                        "type": "tcp",
                        "host": "127.0.0.1",
                        "port": 8080,
                        "interval_sec": 10,
                        "timeout_sec": 2,
                        "initial_delay_sec": 3
                    },
                    "auto_reconnect": True
                }
            ]
        }
        CONFIG_PATH.write_text(
            json.dumps(example, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    raw = CONFIG_PATH.read_text(encoding="utf-8")
    clean = strip_json_comments(raw)
    try:
        return json.loads(clean)
    except json.JSONDecodeError as e:
        # Записываем ошибку в лог чтобы пользователь увидел
        err_log = LOGS_DIR / "config_errors.log"
        try:
            with open(err_log, "w", encoding="utf-8") as f:
                f.write(f"Ошибка парсинга {CONFIG_PATH}:\n\n  {e}\n\n")
                f.write("Проверь JSON-синтаксис: лишние запятые, незакрытые кавычки, и т.д.\n")
                f.write("Онлайн-валидатор: https://jsonlint.com\n")
        except Exception:
            pass
        raise


def validate_config(config: dict) -> list[str]:
    """
    Проверяет конфиг при загрузке. Возвращает список проблем.
    Битые туннели позже отфильтровываются в TunnelManager.__init__,
    но программа всё равно запускается — чтобы можно было исправить конфиг
    через меню "Открыть конфиг", а не редактировать его в темноте.
    """
    errors: list[str] = []

    # ---------- tunnels ----------
    tunnels = config.get("tunnels", [])
    if not isinstance(tunnels, list):
        errors.append("tunnels: должен быть списком")
        tunnels = []
    if not tunnels:
        errors.append("tunnels: пустой список — нечего запускать")

    names: list[str] = []
    seen_names: set[str] = set()

    for i, t in enumerate(tunnels):
        if not isinstance(t, dict):
            errors.append(f"tunnels[{i}]: не словарь")
            continue

        name = t.get("name")
        if not name or not isinstance(name, str):
            errors.append(f"tunnels[{i}]: имя пустое или не строка")
            continue
        if name in seen_names:
            errors.append(f"туннель '{name}': дубликат имени (имя должно быть уникальным)")
        seen_names.add(name)
        names.append(name)

        bat = t.get("bat_path")
        if not t.get("monitor_only", False):
            if not bat or not isinstance(bat, str):
                errors.append(f"туннель '{name}': bat_path пустой (или поставь monitor_only: true)")

    # ---------- зависимости ----------
    name_set = set(names)
    deps = {}
    for t in tunnels:
        if isinstance(t, dict) and t.get("name") in name_set:
            dep = t.get("depends_on")
            if dep:
                if dep not in name_set:
                    errors.append(
                        f"туннель '{t['name']}': зависимость '{dep}' не найдена в конфиге"
                    )
                else:
                    deps[t["name"]] = dep

    # ---------- циклы в зависимостях ----------
    seen_cycles: set[frozenset] = set()
    for start in deps:
        path = [start]
        visited = {start}
        cur = deps.get(start)
        while cur:
            if cur in visited:
                # Нашли цикл — выделяем его подпуть
                cycle_start = path.index(cur)
                cycle = path[cycle_start:] + [cur]
                key = frozenset(cycle)
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    errors.append("цикл в зависимостях: " + " → ".join(cycle))
                break
            path.append(cur)
            visited.add(cur)
            cur = deps.get(cur)

    # ---------- kill switch ----------
    ks = config.get("kill_switch", {})
    if ks.get("enabled"):
        if ks.get("mode") == "firewall":
            fw = ks.get("firewall", {})
            ips = fw.get("vpn_server_ips", [])
            has_program = bool(fw.get("openvpn_exe"))
            has_iface = bool(fw.get("vpn_interface"))
            has_subnet = bool(fw.get("vpn_tunnel_subnet"))
            if PLACEHOLDER_VPN_IP in ips:
                errors.append(
                    f"kill_switch.firewall.vpn_server_ips содержит плейсхолдер "
                    f"'{PLACEHOLDER_VPN_IP}' — замени на реальный IP или удали из списка"
                )
            # Нужен хотя бы один способ выпустить трафик: процесс OpenVPN,
            # имя интерфейса, или (запасной) whitelist IP / подсеть.
            if not (has_program or has_iface or ips or has_subnet):
                errors.append(
                    "kill_switch.firewall: укажи openvpn_exe (рекомендуется) "
                    "или vpn_interface, или vpn_server_ips — иначе нечего разрешить"
                )

        vpn_tunnel = ks.get("vpn_tunnel")
        if vpn_tunnel and vpn_tunnel not in name_set:
            errors.append(
                f"kill_switch.vpn_tunnel='{vpn_tunnel}' не найден среди tunnels"
            )

    return errors


# ============================================================
# Health checks
# ============================================================

def check_tcp(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_ping(host: str, timeout_sec: float) -> bool:
    timeout_ms = int(timeout_sec * 1000)
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), host],
            capture_output=True,
            creationflags=CREATE_NO_WINDOW,
            timeout=timeout_sec + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def check_process_running(image_name: str) -> bool:
    """True если процесс с таким именем (напр. 'openvpn.exe') запущен."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/NH"],
            capture_output=True, creationflags=CREATE_NO_WINDOW,
            timeout=5, text=True, encoding="cp866", errors="replace",
        )
        return image_name.lower() in (result.stdout or "").lower()
    except (subprocess.TimeoutExpired, OSError):
        return False


def check_openvpn(config: dict) -> bool:
    """
    Health-check для OpenVPN GUI: VPN считается живым, только если
      (1) процесс openvpn.exe запущен, И
      (2) если задан host — пинг до него внутри туннеля проходит.
    Это надёжнее голого ping: ping мог бы ответить и без VPN (тот же IP в локалке),
    а проверка процесса ловит «GUI закрыли / VPN отвалился».
    """
    image = config.get("process", "openvpn.exe")
    if not check_process_running(image):
        return False
    host = config.get("host")
    if host:
        return check_ping(host, config.get("timeout_sec", 3))
    return True


def run_health_check(config: dict) -> bool:
    """
    Выполняет health-check согласно конфигу. Возвращает True если всё ОК.

    Для типа 'tcp' поддерживается:
      - один порт:      {"type": "tcp", "host": "127.0.0.1", "port": 5432}
      - несколько:      {"type": "tcp", "host": "127.0.0.1", "ports": [5432, 5433]}
      - host+port пары: {"type": "tcp", "targets": [{"host": "...", "port": ...}, ...]}
    Для нескольких целей: ИЛИ-логика (живой если ХОТЯ БЫ одна проверка прошла).
    """
    check_type = config.get("type", "process")
    timeout = config.get("timeout_sec", 3)

    if check_type == "tcp":
        targets = _tcp_targets(config)
        if not targets:
            return False
        return any(check_tcp(host, port, timeout) for host, port in targets)

    if check_type == "ping":
        return check_ping(config["host"], timeout)

    if check_type == "openvpn":
        return check_openvpn(config)

    # process — проверяется снаружи (по факту жив ли Popen)
    return True


def _tcp_targets(config: dict) -> list[tuple[str, int]]:
    if "targets" in config:
        return [(t["host"], t["port"]) for t in config["targets"]]
    if "ports" in config:
        host = config.get("host", "127.0.0.1")
        return [(host, p) for p in config["ports"]]
    if "port" in config:
        host = config.get("host", "127.0.0.1")
        return [(host, config["port"])]
    return []


# ============================================================
# Backoff для реконнекта
# ============================================================

class Backoff:
    """Backoff: 5, 10, 30, 60, 120 сек. После 5-й попытки фиксируется на 120."""
    SEQUENCE = [5, 10, 30, 60, 120]

    def __init__(self):
        self.attempt = 0

    def next_delay(self) -> int:
        self.attempt += 1
        idx = min(self.attempt - 1, len(self.SEQUENCE) - 1)
        return self.SEQUENCE[idx]

    def reset(self):
        self.attempt = 0


# ============================================================
# Туннель
# ============================================================

@dataclass
class TunnelConfig:
    name: str
    bat_path: str | None = None
    autostart: bool = False
    depends_on: str | None = None
    health_check: dict = field(default_factory=lambda: {"type": "process"})
    auto_reconnect: bool = False
    monitor_only: bool = False  # не запускать .bat, только мониторить статус (для VPN из внешнего GUI)


class Tunnel:
    """
    Один туннель: запуск/остановка bat-файла + health-check + автореконнект.
    Логика крутится в отдельном потоке `_monitor_loop`.
    """

    def __init__(self, cfg: TunnelConfig, manager: "TunnelManager"):
        self.cfg = cfg
        self.manager = manager
        self.process: subprocess.Popen | None = None
        self.status: Status = Status.STOPPED
        self.last_status_change: float = time.time()
        self.backoff = Backoff()

        self._enabled = False
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        safe_name = "".join(c if c.isalnum() else "_" for c in cfg.name)
        self.log_path = LOGS_DIR / f"{safe_name}.log"
        self._log_file = None

    # ---------- внешний API ----------

    def enable(self):
        """Пользователь хочет, чтобы туннель работал. Запускаем монитор."""
        if self._enabled:
            return
        # Если старый поток ещё дёргается (например, после быстрого disable→enable) —
        # дожидаемся его завершения чтобы не плодить параллельные мониторы
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._enabled = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def disable(self):
        """Пользователь хочет остановить. Гасим монитор и процесс."""
        if not self._enabled:
            return
        self._enabled = False
        self._stop_event.set()
        self._kill_process()
        self._set_status(Status.STOPPED)
        # Даём потоку немного времени на корректное завершение, но не блокируем UI
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def open_log(self):
        if not self.log_path.exists():
            self.log_path.write_text("Туннель ещё не запускался.\n", encoding="utf-8")
        os.startfile(str(self.log_path))

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def is_healthy(self) -> bool:
        return self.status == Status.HEALTHY

    # ---------- внутренние методы ----------

    def _set_status(self, new_status: Status):
        if new_status != self.status:
            old = self.status
            self.status = new_status
            self.last_status_change = time.time()
            self._log(f"[STATUS] {old.value} → {new_status.value}")
            self.manager.on_status_change(self, old, new_status)

    def _rotate_log_if_needed(self):
        """Если лог разросся — оставляем последний хвост."""
        try:
            if not self.log_path.exists():
                return
            if self.log_path.stat().st_size <= LOG_MAX_SIZE:
                return
            with open(self.log_path, "rb") as f:
                f.seek(-LOG_KEEP_SIZE, os.SEEK_END)
                tail = f.read()
            with open(self.log_path, "wb") as f:
                f.write(f"[log rotated at {time.strftime('%Y-%m-%d %H:%M:%S')}]\n".encode("utf-8"))
                f.write(tail)
        except Exception:
            pass

    def _log(self, msg: str):
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
        try:
            self._rotate_log_if_needed()
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    def _start_process(self):
        """Запускает bat-файл скрыто. _log_file открывается ТОЛЬКО при успехе."""
        if not Path(self.cfg.bat_path).exists():
            self._log(f"[ОШИБКА] Файл не найден: {self.cfg.bat_path}")
            return False

        # Открываем файл лога в локальную переменную — присвоим в self только
        # после успешного Popen, чтобы избежать утечки если Popen упадёт
        log_file = None
        try:
            log_file = open(self.log_path, "a", encoding="utf-8", buffering=1)
            log_file.write(f"\n=== Запуск {self.cfg.name} ===\n")

            self.process = subprocess.Popen(
                ["cmd.exe", "/c", self.cfg.bat_path],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                cwd=str(Path(self.cfg.bat_path).parent),
            )
            self._log_file = log_file
            return True
        except Exception as e:
            self._log(f"[ОШИБКА запуска] {e}")
            if log_file is not None:
                try:
                    log_file.close()
                except Exception:
                    pass
            return False

    def _kill_process(self):
        """Жёстко убивает процесс и всё дерево потомков."""
        if self.process and self.process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                    creationflags=CREATE_NO_WINDOW,
                    capture_output=True,
                    timeout=5,
                )
            except Exception as e:
                self._log(f"[ОШИБКА taskkill] {e}")
        self.process = None
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

    def _process_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _wait_for_dependency(self) -> bool:
        if not self.cfg.depends_on:
            return True

        dep = self.manager.get_tunnel(self.cfg.depends_on)
        if dep is None:
            self._log(f"[ВНИМАНИЕ] Зависимость '{self.cfg.depends_on}' не найдена в конфиге")
            return True

        self._set_status(Status.WAITING_DEP)
        self._log(f"Ожидание готовности зависимости: {self.cfg.depends_on}")

        while not self._stop_event.is_set():
            if dep.is_healthy:
                self._log(f"Зависимость '{self.cfg.depends_on}' готова")
                return True
            if self._stop_event.wait(2):
                return False
        return False

    def _dependency_dead(self) -> bool:
        if not self.cfg.depends_on:
            return False
        dep = self.manager.get_tunnel(self.cfg.depends_on)
        if dep is None:
            return False
        return not dep.is_healthy

    def _monitor_loop(self):
        # Monitor-only туннель: ничего не запускаем, только следим за статусом.
        # Используется для VPN, который поднимается внешним клиентом (OpenVPN GUI):
        # программа лишь определяет жив ли VPN, а зависимые туннели стартуют по этому статусу.
        if self.cfg.monitor_only:
            self._monitor_only_loop()
            return

        hc = self.cfg.health_check
        interval = hc.get("interval_sec", 10)
        initial_delay = hc.get("initial_delay_sec", 5)

        while not self._stop_event.is_set() and self._enabled:

            # 1. Ждём зависимость
            if not self._wait_for_dependency():
                break

            # 2. Запускаем процесс
            self._set_status(Status.STARTING)
            if not self._start_process():
                self._reconnect_wait()
                continue

            # 3. Initial delay
            if self._stop_event.wait(initial_delay):
                break

            # 4. Health-check цикл
            consecutive_fails = 0
            while not self._stop_event.is_set() and self._enabled:
                if self._dependency_dead():
                    self._log(f"[FAIL] Зависимость '{self.cfg.depends_on}' стала недоступна")
                    break

                if not self._process_alive():
                    self._log("[FAIL] Процесс завершился")
                    break

                ok = run_health_check(hc) if hc.get("type") != "process" else True

                if ok:
                    if self.status != Status.HEALTHY:
                        self._set_status(Status.HEALTHY)
                        self.backoff.reset()
                    consecutive_fails = 0
                else:
                    consecutive_fails += 1
                    self._log(f"[FAIL] Health-check #{consecutive_fails}")
                    if consecutive_fails >= 2:
                        self._set_status(Status.UNHEALTHY)
                        break

                if self._stop_event.wait(interval):
                    break

            # 5. Cleanup
            dep_was_reason = self._dependency_dead()
            self._kill_process()

            if not self._enabled or self._stop_event.is_set():
                break

            # 6. Реконнект
            if not self.cfg.auto_reconnect:
                self._set_status(Status.STOPPED)
                self._enabled = False
                break

            if dep_was_reason:
                self.backoff.reset()
                continue

            self._reconnect_wait()

    def _reconnect_wait(self):
        delay = self.backoff.next_delay()
        self._set_status(Status.RECONNECTING)
        self._log(f"Реконнект через {delay} сек (попытка #{self.backoff.attempt})")
        self._stop_event.wait(delay)

    def _monitor_only_loop(self):
        """
        Цикл для monitor_only туннеля. Ничего не запускает и не убивает —
        только периодически проверяет health-check и выставляет статус
        HEALTHY/UNHEALTHY. Зависимые туннели реагируют на этот статус.
        """
        hc = self.cfg.health_check
        interval = hc.get("interval_sec", 10)
        initial_delay = hc.get("initial_delay_sec", 5)

        self._set_status(Status.STARTING)
        self._log("Monitor-only режим: слежу за внешним подключением (запуск .bat не выполняется)")

        if self._stop_event.wait(initial_delay):
            self._set_status(Status.STOPPED)
            return

        while not self._stop_event.is_set() and self._enabled:
            ok = run_health_check(hc) if hc.get("type") != "process" else True
            if ok:
                if self.status != Status.HEALTHY:
                    self._set_status(Status.HEALTHY)
                    self.backoff.reset()
            else:
                if self.status != Status.UNHEALTHY:
                    self._set_status(Status.UNHEALTHY)
            if self._stop_event.wait(interval):
                break

        self._set_status(Status.STOPPED)


# ============================================================
# Менеджер
# ============================================================

class TunnelManager:
    def __init__(self):
        config = load_config()

        # Валидация конфига. Ошибки записываются в logs/config_errors.log
        # и показываются пользователю в трее, но программа всё равно запускается
        # с тем, что валидно — чтобы пользователь мог открыть конфиг из меню
        self._config_errors = validate_config(config)
        if self._config_errors:
            self._write_config_errors()

        self.tunnels: list[Tunnel] = []
        seen_names: set[str] = set()
        for t in config.get("tunnels", []):
            if not isinstance(t, dict):
                continue
            name = t.get("name")
            bat = t.get("bat_path")
            monitor_only = t.get("monitor_only", False)
            if not name or name in seen_names:
                continue
            if not monitor_only and not bat:
                continue  # обычному туннелю нужен bat (уже залогировано в validate_config)
            seen_names.add(name)
            cfg = TunnelConfig(
                name=name,
                bat_path=bat,
                autostart=t.get("autostart", False),
                depends_on=t.get("depends_on"),
                health_check=t.get("health_check", {"type": "process"}),
                auto_reconnect=t.get("auto_reconnect", False),
                monitor_only=monitor_only,
            )
            self.tunnels.append(Tunnel(cfg, self))

        self.ks_config = config.get("kill_switch", {"enabled": False})
        self.ks_firewall_active = False

        # Чистим залипшие firewall-правила ТОЛЬКО если KS включён в конфиге.
        # Раньше cleanup запускался при любом старте с админ-правами — это
        # неожиданно стирало правила если человек выключил KS в конфиге,
        # но хотел чтобы они оставались
        if self.ks_config.get("enabled") and kill_switch.is_admin():
            kill_switch.cleanup_firewall_rules(logger=self._ks_log)

        atexit.register(self._cleanup_on_exit)

        self.icon: pystray.Icon | None = None

        # Debounce уведомлений: {текст_уведомления: последний_timestamp}
        self._notification_history: dict[str, float] = {}

        # Кэш состояния admin-автозапуска (чтобы не дёргать schtasks каждые 2 сек при перерисовке меню)
        self._admin_autostart_cached = is_admin_autostart_enabled()

    def _write_config_errors(self):
        err_log = LOGS_DIR / "config_errors.log"
        try:
            with open(err_log, "w", encoding="utf-8") as f:
                f.write(f"Проблемы в {CONFIG_PATH}\n")
                f.write(f"Дата: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for e in self._config_errors:
                    f.write(f"  • {e}\n")
                f.write("\nПрограмма запустилась с теми туннелями, которые удалось распарсить.\n")
                f.write("Открой tunnels.json из меню в трее и поправь конфиг, затем перезапусти.\n")
        except Exception:
            pass

    def _ks_log(self, msg: str):
        log_path = LOGS_DIR / "kill_switch.log"
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    def _activate_firewall_killswitch(self) -> bool:
        ks = self.ks_config
        fw = ks.get("firewall", {})

        ips = fw.get("vpn_server_ips", [])
        ports = fw.get("vpn_server_ports", [])
        protocols = fw.get("vpn_protocols", ["udp"])

        # vpn_interface может быть строкой или списком — нормализуем в список
        iface = fw.get("vpn_interface")
        if isinstance(iface, str):
            iface = [iface] if iface.strip() else None
        elif not iface:
            iface = None

        # Защита от случайной блокировки на дефолтном IP из шаблона
        if PLACEHOLDER_VPN_IP in ips:
            self._ks_log(
                f"[FW ERROR] vpn_server_ips содержит плейсхолдер '{PLACEHOLDER_VPN_IP}' — "
                f"kill switch НЕ включен. Замени на реальный IP или удали из списка."
            )
            return False

        # Нужен хотя бы один способ выпустить трафик наружу/в туннель.
        has_program = bool(fw.get("openvpn_exe")) or kill_switch.detect_openvpn_exe() is not None
        has_subnet = bool(fw.get("vpn_tunnel_subnet"))
        if not (has_program or iface or ips or has_subnet):
            self._ks_log(
                "[FW ERROR] Нечего разрешить: не задан openvpn_exe / vpn_interface / "
                "vpn_server_ips / vpn_tunnel_subnet — kill switch не включен"
            )
            return False

        ok = kill_switch.enable_firewall_killswitch(
            vpn_server_ips=ips,
            vpn_server_ports=ports,
            vpn_protocols=protocols,
            allow_local_network=fw.get("allow_local_network", True),
            inbound_allow=fw.get("inbound_allow", []),
            vpn_tunnel_subnet=fw.get("vpn_tunnel_subnet"),
            openvpn_exe=fw.get("openvpn_exe") or None,
            vpn_interface_aliases=iface,
            logger=self._ks_log,
        )
        if ok:
            self.ks_firewall_active = True
            write_emergency_bat()
        return ok

    def _cleanup_on_exit(self):
        if not self.ks_firewall_active:
            return
        fw = self.ks_config.get("firewall", {})
        if fw.get("cleanup_on_exit", False):
            kill_switch.disable_firewall_killswitch(logger=self._ks_log)
            self.ks_firewall_active = False
        else:
            self._ks_log(
                "[FW] cleanup_on_exit=false — правила оставлены в firewall. "
                "Интернет остаётся заблокированным (кроме VPN-сервера и разрешённых правил) "
                "до следующего запуска программы."
            )

    def get_tunnel(self, name: str) -> Tunnel | None:
        for t in self.tunnels:
            if t.cfg.name == name:
                return t
        return None

    def on_status_change(self, tunnel: Tunnel, old: Status, new: Status):
        self._handle_killswitch_status(tunnel, old, new)

        if self.icon is None:
            return

        if new == Status.HEALTHY and old in (Status.STARTING, Status.RECONNECTING, Status.UNHEALTHY):
            self._notify(f"{tunnel.cfg.name}: подключено ✓")
        elif new == Status.UNHEALTHY:
            self._notify(f"{tunnel.cfg.name}: соединение потеряно ✗")

        self._refresh_icon()

    def _handle_killswitch_status(self, tunnel: Tunnel, old: Status, new: Status):
        ks = self.ks_config
        if not ks.get("enabled"):
            return

        vpn_name = ks.get("vpn_tunnel")
        if not vpn_name or tunnel.cfg.name != vpn_name:
            return

        mode = ks.get("mode", "tunnels_only")
        if mode == "firewall":
            return

        # tunnels_only: VPN упал — убиваем процессы
        if new in (Status.UNHEALTHY, Status.RECONNECTING, Status.STOPPED) \
                and old == Status.HEALTHY:
            self._ks_log(f"VPN '{vpn_name}' упал ({old.value} → {new.value}) — убиваю процессы")
            kill_procs = ks.get("kill_processes", [])
            if kill_procs:
                kill_switch.kill_processes_by_name(kill_procs, logger=self._ks_log)
            self._notify("⚠ VPN упал — процессы остановлены")
        elif new == Status.HEALTHY and old != Status.HEALTHY:
            self._notify("✓ VPN восстановлен")

    def _notify(self, message: str):
        """Debounce: одинаковые сообщения не чаще раза в NOTIFICATION_DEBOUNCE_SEC."""
        now = time.time()
        last = self._notification_history.get(message, 0)
        if now - last < NOTIFICATION_DEBOUNCE_SEC:
            return
        self._notification_history[message] = now
        # Подчищаем старые записи чтобы dict не рос вечно
        if len(self._notification_history) > 100:
            cutoff = now - NOTIFICATION_DEBOUNCE_SEC * 2
            self._notification_history = {
                k: v for k, v in self._notification_history.items() if v > cutoff
            }
        try:
            if self.icon:
                self.icon.notify(message, title=APP_NAME)
        except Exception:
            pass

    def start_all_autostart(self):
        for t in self.tunnels:
            if t.cfg.autostart:
                t.enable()

    def stop_all(self):
        for t in self.tunnels:
            t.disable()

    # ---------- меню ----------

    def _toggle(self, tunnel: Tunnel):
        def handler(icon, item):
            if tunnel.is_enabled:
                tunnel.disable()
            else:
                tunnel.enable()
            self._refresh_icon()
        return handler

    def _open_log(self, tunnel: Tunnel):
        return lambda icon, item: tunnel.open_log()

    def _start_all(self, icon, item):
        for t in self.tunnels:
            if not t.is_enabled:
                t.enable()
        self._refresh_icon()

    def _stop_all(self, icon, item):
        self.stop_all()
        self._refresh_icon()

    def _toggle_autostart(self, icon, item):
        new = not is_autostart_enabled()
        set_autostart(new)
        if new and self._admin_autostart_cached:
            # Обычный автостарт запускает БЕЗ админа — убираем admin-задачу,
            # иначе при логине будет гонка двух запусков (mutex пропустит только один)
            set_admin_autostart(False)
            self._admin_autostart_cached = False

    def _toggle_admin_autostart(self, icon, item):
        enabled = self._admin_autostart_cached
        if not enabled and not kill_switch.is_admin():
            self._notify("⚠ Чтобы настроить автозапуск от админа, запусти программу от администратора")
            return
        ok, out = set_admin_autostart(not enabled)
        if ok:
            self._admin_autostart_cached = not enabled
            if not enabled:
                # Включили admin-задачу — убираем обычный реестровый автостарт
                set_autostart(False)
                self._notify("✓ Автозапуск от админа включён (без UAC при входе)")
            else:
                self._notify("✓ Автозапуск от админа выключен")
        else:
            self._notify("⚠ Не удалось изменить задачу автозапуска")
            self._ks_log(f"[TASK] schtasks: {out.strip()}")
        self._refresh_icon()

    def _open_config(self, icon, item):
        os.startfile(str(CONFIG_PATH))

    def _open_logs_dir(self, icon, item):
        os.startfile(str(LOGS_DIR))

    def _panic_disable_ks(self, icon, item):
        """Аварийно снять firewall kill switch прямо из меню (нужен админ)."""
        if not kill_switch.is_admin():
            self._notify("⚠ Нужны права админа. Запусти '" + EMERGENCY_BAT.name + "' от администратора")
            return
        kill_switch.disable_firewall_killswitch(logger=self._ks_log)
        self.ks_firewall_active = False
        self._notify("✓ Kill switch снят — интернет разблокирован")
        self._refresh_icon()

    def _open_config_errors(self, icon, item):
        err_log = LOGS_DIR / "config_errors.log"
        if err_log.exists():
            os.startfile(str(err_log))

    def _reload_config(self, icon, item):
        """Перезагружает конфиг без перезапуска программы."""
        # 1. Останавливаем все туннели
        self.stop_all()
        time.sleep(1)

        # 2. Перечитываем конфиг
        try:
            config = load_config()
        except json.JSONDecodeError as e:
            self._notify(f"⚠ Ошибка в конфиге: {e}")
            self._refresh_icon()
            return

        # 3. Валидация
        self._config_errors = validate_config(config)
        if self._config_errors:
            self._write_config_errors()

        # 4. Пересоздаём список туннелей
        self.tunnels = []
        seen_names: set[str] = set()
        for t in config.get("tunnels", []):
            if not isinstance(t, dict):
                continue
            name = t.get("name")
            bat = t.get("bat_path")
            monitor_only = t.get("monitor_only", False)
            if not name or name in seen_names:
                continue
            if not monitor_only and not bat:
                continue
            seen_names.add(name)
            cfg = TunnelConfig(
                name=name,
                bat_path=bat,
                autostart=t.get("autostart", False),
                depends_on=t.get("depends_on"),
                health_check=t.get("health_check", {"type": "process"}),
                auto_reconnect=t.get("auto_reconnect", False),
                monitor_only=monitor_only,
            )
            self.tunnels.append(Tunnel(cfg, self))

        # 5. Перечитываем kill switch конфиг
        old_ks_active = self.ks_firewall_active
        self.ks_config = config.get("kill_switch", {"enabled": False})

        # Если KS включён и мы админы — переприменяем правила (cleanup + add)
        if self.ks_config.get("enabled") and self.ks_config.get("mode") == "firewall":
            if kill_switch.is_admin():
                self._activate_firewall_killswitch()
        elif old_ks_active:
            # KS был активен, но в новом конфиге выключен — снимаем правила
            kill_switch.disable_firewall_killswitch(logger=self._ks_log)
            self.ks_firewall_active = False

        # 6. Запускаем autostart-туннели
        self.start_all_autostart()
        self._refresh_icon()

        if self._config_errors:
            self._notify(f"⚠ Конфиг: {len(self._config_errors)} ошибок — см. logs/config_errors.log")
        else:
            self._notify("✓ Конфиг перезагружен")

    def _quit(self, icon, item):
        self.stop_all()
        time.sleep(1)
        self._cleanup_on_exit()
        icon.stop()

    def _status_emoji(self, t: Tunnel) -> str:
        return {
            Status.STOPPED: "⚪",
            Status.STARTING: "🟡",
            Status.HEALTHY: "🟢",
            Status.UNHEALTHY: "🔴",
            Status.WAITING_DEP: "⏳",
            Status.RECONNECTING: "🟠",
        }.get(t.status, "❓")

    def _build_menu(self):
        items = []

        # Если есть ошибки конфига — пункт сверху, чтобы заметно было
        if self._config_errors:
            items.append(pystray.MenuItem(
                f"⚠ Ошибок в конфиге: {len(self._config_errors)} (открыть)",
                self._open_config_errors,
            ))
            items.append(pystray.Menu.SEPARATOR)

        for tunnel in self.tunnels:
            label = f"{self._status_emoji(tunnel)} {tunnel.cfg.name}"
            submenu = pystray.Menu(
                pystray.MenuItem(
                    "Остановить" if tunnel.is_enabled else "Запустить",
                    self._toggle(tunnel),
                ),
                pystray.MenuItem("Открыть лог", self._open_log(tunnel)),
            )
            items.append(pystray.MenuItem(label, submenu))

        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Запустить все", self._start_all))
        items.append(pystray.MenuItem("Остановить все", self._stop_all))

        if self.ks_config.get("enabled"):
            items.append(pystray.Menu.SEPARATOR)
            mode = self.ks_config.get("mode", "tunnels_only")
            if mode == "firewall":
                if self.ks_firewall_active:
                    label = "🛡 Kill Switch (firewall): АКТИВЕН"
                else:
                    label = "🛡 Kill Switch (firewall): НЕ АКТИВЕН (нет админ-прав?)"
                items.append(pystray.MenuItem(label, None, enabled=False))
                items.append(pystray.MenuItem(
                    "🚨 Снять Kill Switch сейчас", self._panic_disable_ks,
                    enabled=self.ks_firewall_active,
                ))
            else:
                label = "🛡 Kill Switch (tunnels): на страже"
                items.append(pystray.MenuItem(label, None, enabled=False))

        items.append(pystray.Menu.SEPARATOR)
        items.append(
            pystray.MenuItem(
                "Автостарт Windows (обычный)",
                self._toggle_autostart,
                checked=lambda item: is_autostart_enabled(),
            )
        )
        items.append(
            pystray.MenuItem(
                "Автозапуск от админа (без UAC)",
                self._toggle_admin_autostart,
                checked=lambda item: self._admin_autostart_cached,
            )
        )
        items.append(pystray.MenuItem("Открыть конфиг (tunnels.json)", self._open_config))
        items.append(pystray.MenuItem("🔄 Перезагрузить конфиг", self._reload_config))
        items.append(pystray.MenuItem("Открыть папку логов", self._open_logs_dir))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Выход", self._quit))
        return pystray.Menu(*items)

    def _refresh_icon(self):
        if self.icon is None:
            return
        healthy = sum(1 for t in self.tunnels if t.is_healthy)
        problems = sum(1 for t in self.tunnels if t.status in (Status.UNHEALTHY, Status.RECONNECTING))
        self.icon.icon = make_icon(healthy, problems)
        self.icon.menu = self._build_menu()
        self.icon.title = f"{APP_NAME} — активно: {healthy}/{len(self.tunnels)}"

    def _periodic_refresh(self):
        while True:
            time.sleep(2)
            try:
                self._refresh_icon()
            except Exception:
                pass

    def run(self):
        # Firewall kill switch при старте (always-on)
        if self.ks_config.get("enabled") and self.ks_config.get("mode") == "firewall":
            if not kill_switch.is_admin():
                self._ks_log(
                    "[ВНИМАНИЕ] Kill switch в режиме 'firewall' требует прав администратора. "
                    "Программа запущена без них — kill switch НЕ АКТИВЕН. "
                    "Запусти от админа или переключи режим на 'tunnels_only' в конфиге."
                )
            else:
                self._activate_firewall_killswitch()

        self.start_all_autostart()
        self.icon = pystray.Icon(
            APP_NAME,
            icon=make_icon(0, 0),
            title=APP_NAME,
            menu=self._build_menu(),
        )

        # Если есть ошибки конфига — уведомление сразу после старта иконки
        if self._config_errors:
            threading.Timer(
                1.5,
                lambda: self._notify(
                    f"⚠ Конфиг содержит {len(self._config_errors)} ошибок — "
                    f"см. logs/config_errors.log"
                ),
            ).start()

        threading.Thread(target=self._periodic_refresh, daemon=True).start()
        self.icon.run()


# ============================================================
# Автостарт Windows
# ============================================================

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def get_exe_path() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    return f'"{sys.executable}" "{Path(__file__).resolve()}"'


def is_autostart_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except FileNotFoundError:
        return False


def set_autostart(enabled: bool):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, get_exe_path())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


# ============================================================
# Автозапуск ОТ АДМИНА без UAC — через Task Scheduler
# ============================================================
# Реестровый автостарт (HKCU\...\Run) запускает БЕЗ прав админа, и если на .exe
# стоит "запускать от администратора" — выскочит UAC-промпт.
# Так делает OpenVPN GUI: задача в Планировщике с "наивысшими правами" запускает
# процесс elevated при входе в систему, БЕЗ запроса пароля/подтверждения.

TASK_NAME = APP_NAME  # имя задачи в Планировщике


def _schtasks(args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["schtasks"] + args,
            creationflags=CREATE_NO_WINDOW,
            capture_output=True,
            timeout=10,
            text=True,
            encoding="cp866",
            errors="replace",
        )
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except Exception as e:
        return False, str(e)


def is_admin_autostart_enabled() -> bool:
    """Проверяет, существует ли задача автозапуска в Планировщике."""
    ok, _ = _schtasks(["/Query", "/TN", TASK_NAME])
    return ok


def set_admin_autostart(enabled: bool) -> tuple[bool, str]:
    """
    Создаёт/удаляет задачу автозапуска от админа.
    Создание требует прав администратора (из-за /RL HIGHEST).
    """
    if enabled:
        # /SC ONLOGON — при входе в систему
        # /RL HIGHEST — с наивысшими правами (elevated, без UAC-промпта)
        # /F — перезаписать если уже есть
        run_cmd = get_exe_path()  # уже с кавычками
        return _schtasks([
            "/Create", "/TN", TASK_NAME, "/TR", run_cmd,
            "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
        ])
    else:
        return _schtasks(["/Delete", "/TN", TASK_NAME, "/F"])


# ============================================================
# Аварийное снятие kill switch (генерируем .bat рядом с программой)
# ============================================================
# Если интернет ляжет и сама программа не стартует — пользователю нужен
# гарантированный способ снять правила. Кладём готовый bat рядом с .exe.
# Запускать от админа (ПКМ → Запуск от администратора).

EMERGENCY_BAT = APP_DIR / "ОТКЛЮЧИТЬ-killswitch.bat"


def write_emergency_bat():
    content = (
        "@echo off\r\n"
        "chcp 65001 >nul\r\n"
        "net session >nul 2>&1\r\n"
        "if %errorlevel% neq 0 (\r\n"
        "  echo Запусти этот файл ОТ АДМИНИСТРАТОРА (ПКМ - Запуск от имени администратора).\r\n"
        "  pause & exit /b 1\r\n"
        ")\r\n"
        "echo Снимаю kill switch (firewall-правила TunnelTray)...\r\n"
        "powershell -NoProfile -Command \"Remove-NetFirewallRule -Group 'TunnelTrayKillSwitch' "
        "-ErrorAction SilentlyContinue\"\r\n"
        "echo Восстанавливаю исходящую политику firewall...\r\n"
        "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound\r\n"
        "echo Готово. Интернет восстановлен.\r\n"
        "pause\r\n"
    )
    try:
        EMERGENCY_BAT.write_text(content, encoding="utf-8")
    except Exception:
        pass




def make_icon(healthy: int, problems: int) -> Image.Image:
    """
    Зелёный с цифрой — если есть healthy туннели и нет проблем.
    Красный с цифрой проблем — если есть упавшие/реконнектящиеся.
    Серый — если ничего не запущено.
    """
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    if problems > 0:
        color = (244, 67, 54)
        count = problems
    elif healthy > 0:
        color = (76, 175, 80)
        count = healthy
    else:
        color = (120, 120, 120)
        count = 0

    draw.ellipse([4, 4, size - 4, size - 4], fill=color)

    if count > 0:
        try:
            font = ImageFont.truetype("arial.ttf", 36)
        except OSError:
            font = ImageFont.load_default()
        text = str(count) if count < 10 else "9+"
        bbox = draw.textbbox((0, 0), text, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(
            ((size - w) / 2 - bbox[0], (size - h) / 2 - bbox[1]),
            text, fill="white", font=font,
        )
    return img


# ============================================================

if __name__ == "__main__":
    # Single-instance защита: если уже запущена копия, тихо выходим
    _mutex_handle = acquire_single_instance()
    if _mutex_handle is None:
        sys.exit(0)

    try:
        TunnelManager().run()
    finally:
        # Освобождаем mutex при штатном выходе. На креш Windows закроет сама.
        if _mutex_handle and _mutex_handle != -1:
            try:
                ctypes.windll.kernel32.CloseHandle(_mutex_handle)
            except Exception:
                pass
