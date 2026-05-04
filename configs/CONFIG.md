# Конфигурация DPI-прототипа

Этот файл описывает формат TOML-конфига для текущей версии программы.

Пример базового файла: [dpi.toml](dpi.toml)
Пример для Docker: [dpi.docker.toml](dpi.docker.toml)

## Общие правила

- Формат: TOML.
- Конфиг читается один раз на старте.
- Неизвестные ключи считаются ошибкой запуска.
- Для строк и списков применяется trim пробелов.
- Для `dns.blocked_domains` домены приводятся к нижнему регистру и дедуплицируются.
- Для `firewall.blocked_ips` список дедуплицируется.

## Полная схема

```toml
[app]
log_level = "info"

[dns]
enabled = false
config_path = "/etc/dnsmasq.d/dpi.conf"
reload_command = ["systemctl", "reload", "dnsmasq"]
blocked_domains = ["rutracker.org", "example.com"]

[firewall]
enabled = false
family = "inet"
table = "dpi"
chain = "input"
set_name = "blocked_ips"
blocked_ips = ["203.0.113.10"]

[inspector]
enabled = true
queue_num = 0
fail_open = true
mode = "skeleton"
```

## Раздел `[app]`

### `log_level`
- Тип: `string`
- По умолчанию: `"info"`
- Примеры: `"debug"`, `"info"`, `"warn"`, `"error"`
- Поведение:
  - пустая строка -> ошибка;
  - значение приводится к lower-case.
  - при `debug` в режиме NFQUEUE возможна заметная нагрузка на CPU из-за подробного логирования.

## Раздел `[dns]`

### `enabled`
- Тип: `bool`
- По умолчанию: `false`
- Включает генерацию конфигурации `dnsmasq` и выполнение reload-команды.

### `config_path`
- Тип: `string`
- По умолчанию: `"/etc/dnsmasq.d/dpi.conf"`
- Путь, куда будет записан сгенерированный файл `dnsmasq`.
- Если `dns.enabled = true`, поле не должно быть пустым.

### `reload_command`
- Тип: `array[string]`
- По умолчанию: `["systemctl", "reload", "dnsmasq"]`
- Команда reload после обновления `config_path`.
- Если `dns.enabled = true`, массив не должен быть пустым.

### `blocked_domains`
- Тип: `array[string]`
- По умолчанию: `[]`
- Список блокируемых доменов.
- Используется двумя подсистемами:
  - DNS (`dnsmasq`) генерирует строки `address=/domain/0.0.0.0`;
  - инспектор блокирует HTTP Host и TLS SNI по этим же доменам (включая поддомены).
- Нормализация:
  - trim пробелов;
  - lower-case;
  - удаление дубликатов;
  - пустые элементы игнорируются.

## Раздел `[firewall]`

### `enabled`
- Тип: `bool`
- По умолчанию: `false`
- Включает настройку `nftables` и загрузку IP в set.

### `family`
- Тип: `string`
- По умолчанию: `"inet"`
- Обычно варианты: "ip", "ip6", "inet", "arp", "bridge", "netdev"
- Семейство таблиц `nft`.
- Если `firewall.enabled = true`, поле не должно быть пустым.

### `table`
- Тип: `string`
- По умолчанию: `"dpi"`
- Имя таблицы `nft`.
- Если `firewall.enabled = true`, поле не должно быть пустым.

### `chain`
- Тип: `string`
- По умолчанию: `"input"`
- Имя chain, где добавляется правило drop.
- Если `firewall.enabled = true`, поле не должно быть пустым.

### `set_name`
- Тип: `string`
- По умолчанию: `"blocked_ips"`
- Имя `nft` set для блокируемых IP.
- Если `firewall.enabled = true`, поле не должно быть пустым.

### `blocked_ips`
- Тип: `array[string]`
- По умолчанию: `[]`
- Список IP для добавления в set.
- Если `firewall.enabled = true`, каждый IP проходит валидацию (`net.ParseIP`).
- Нормализация:
  - trim пробелов;
  - удаление дубликатов;
  - пустые элементы игнорируются.

## Раздел `[inspector]`

### `enabled`
- Тип: `bool`
- По умолчанию: `true`
- Включает запуск цикла инспектора NFQUEUE.
- Важно: для реального перехвата пакетов вместе с этим должен быть включён `firewall.enabled`, чтобы программа поставила `nft` queue rule.

### `queue_num`
- Тип: `uint16`
- По умолчанию: `0`
- Номер очереди NFQUEUE (допустимый диапазон `0..65535`).

### `fail_open`
- Тип: `bool`
- По умолчанию: `true`
- Политика на ошибки/неразбираемые пакеты.
- `true`: на ошибках парсинга пакет пропускается.
- `false`: на ошибках парсинга пакет блокируется.

### `mode`
- Тип: `string`
- По умолчанию: `"skeleton"`
- Режим работы инспектора.
- В текущей версии поддерживается базовый пакетный анализ:
  - блокировка BitTorrent handshake по сигнатуре `\x13BitTorrent protocol`;
  - блокировка HTTP Host по доменам из `dns.blocked_domains`.
  - блокировка TLS SNI из ClientHello по доменам из `dns.blocked_domains`.
  - блокировка OpenVPN по сигнатурам как на TCP так и по UDP.
- Пустая строка -> ошибка.

## Примеры

### 1) Локальный запуск на macOS (без dns/firewall)

```toml
[app]
log_level = "info"

[dns]
enabled = false

[firewall]
enabled = false

[inspector]
enabled = true
queue_num = 0
fail_open = true
mode = "skeleton"
```

### 2) Контейнерный запуск (dns + firewall включены)

```toml
[app]
log_level = "info"

[dns]
enabled = true
config_path = "/etc/dnsmasq.d/dpi.conf"
reload_command = ["sh", "-c", "if pidof dnsmasq >/dev/null 2>&1; then kill -HUP $(pidof dnsmasq); fi"]
blocked_domains = ["blocked.example", "rutracker.org"]

[firewall]
enabled = true
family = "inet"
table = "dpi"
chain = "input"
set_name = "blocked_ips"
blocked_ips = ["203.0.113.10", "198.51.100.15"]

[inspector]
enabled = true
queue_num = 0
fail_open = true
mode = "skeleton"
```

### 3) Минимально валидный конфиг

```toml
# Все поля возьмутся из значений по умолчанию
```

## Частые ошибки

- Лишние ключи в TOML -> ошибка `unknown TOML keys`.
- `dns.enabled = true` и пустой `config_path`/`reload_command` -> ошибка валидации.
- `firewall.enabled = true` и невалидный IP в `blocked_ips` -> ошибка валидации.
- Пустой `app.log_level` или `inspector.mode` -> ошибка валидации.
