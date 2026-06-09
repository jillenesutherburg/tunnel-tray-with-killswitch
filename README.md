# Tunnel Tray Manager

Утилита для управления `.bat`-файлами туннелей (OpenVPN, SSH, WireGuard и т.д.) через системный трей Windows, с health-чеками, автореконнектом, зависимостями между туннелями и параноидальным kill switch.

![icon](app.ico)

## Возможности

- 🟢 **Health-check** каждого туннеля: TCP-коннект, ping или просто факт жизни процесса
- 🔁 **Автореконнект** с экспоненциальным backoff (5 → 10 → 30 → 60 → 120 сек)
- 🔗 **Зависимости**: туннель B стартует только после готовности туннеля A
- 🛡 **Kill switch** в двух режимах:
  - `firewall` — настоящий always-on (требует админа), весь трафик только через VPN
  - `tunnels_only` — без админа, рубит туннели и процессы при падении VPN
- 🎨 Цветовая индикация статуса в иконке трея
- 🔔 Уведомления о падении / восстановлении (с debounce от спама)
- 🚀 Автостарт Windows через реестр
- 🔒 **Single-instance защита** — двойной клик не плодит дубликаты
- ✅ **Валидация конфига** на старте: проверка дубликатов имён, битых зависимостей, циклов
- 🔄 Ротация логов туннелей (>5 МБ → оставляем последние 2 МБ)

## Скачать готовый .exe

Из [Releases](../../releases) — последняя стабильная версия. Или из [Actions](../../actions) — артефакт `TunnelTrayManager-<sha>` последнего успешного билда.

## Запуск

1. Положи `TunnelTrayManager.exe` в любую папку, например `C:\TunnelTray\`
2. Запусти один раз — программа создаст рядом `tunnels.json` с примером конфига и подпапку `logs/`
3. Отредактируй `tunnels.json` под свои `.bat`-файлы (см. ниже)
4. Перезапусти

Для firewall-режима kill switch программу нужно запускать **от админа**: ПКМ на `.exe` → Запуск от имени администратора. Чтобы это происходило всегда — ПКМ → Свойства → Совместимость → "Запускать от имени администратора".

## Конфиг

Полная документация по kill switch — в [KILL_SWITCH.md](KILL_SWITCH.md).

Минимальный пример без kill switch:

```json
{
  "kill_switch": { "enabled": false },
  "tunnels": [
    {
      "name": "my_tunnel",
      "bat_path": "C:\\tunnels\\my_tunnel.bat",
      "autostart": true,
      "depends_on": null,
      "health_check": {
        "type": "tcp",
        "host": "127.0.0.1",
        "port": 5432,
        "interval_sec": 10,
        "timeout_sec": 2,
        "initial_delay_sec": 5
      },
      "auto_reconnect": true
    }
  ]
}
```

### Типы health-check

| `type` | Когда выбрать | Дополнительные поля |
|---|---|---|
| `tcp` | Туннель пробрасывает порт (SSH, БД, прокси) | `host`, `port` *или* `ports: []` *или* `targets: [{host, port}]` |
| `ping` | Туннель — это VPN с известным IP внутри сети | `host` |
| `process` | Нет способа проверить снаружи, верим что процесс жив | — |

### Зависимости

`depends_on: "имя_другого_туннеля"` — этот туннель стартует только когда зависимость в статусе `HEALTHY`. Если зависимость падает — этот туннель тоже останавливается и ждёт пока зависимость не восстановится.

Циклы (A → B → A) детектируются при загрузке и репортятся в `logs/config_errors.log`.

## Логи

В подпапке `logs/` рядом с `.exe`:
- `<имя_туннеля>.log` — вывод bat-файла + события статуса (с автоматической ротацией)
- `kill_switch.log` — события firewall kill switch
- `config_errors.log` — список проблем в `tunnels.json` (только если они есть)

## Сборка из исходников

```cmd
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --noconsole --onefile --icon=app.ico --name TunnelTrayManager tunnel_tray.py
```

Готовый `.exe` появится в `dist/`.

## Что в репозитории

| Файл | Что это |
|---|---|
| `tunnel_tray.py` | основной код: трей, мониторинг, реконнект |
| `kill_switch.py` | модуль firewall kill switch |
| `app.ico` | иконка для `.exe` (multi-size: 16/24/32/48/64/128/256) |
| `requirements.txt` | runtime-зависимости (pystray, Pillow) |
| `.github/workflows/build.yml` | GitHub Actions: автосборка `.exe` на windows-latest |
| `KILL_SWITCH.md` | детальная документация по kill switch |
| `CHANGELOG.md` | история изменений |
| `.gitignore` | исключения для Python + runtime файлы |
