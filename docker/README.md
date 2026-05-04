# Docker-окружение

Эта директория содержит Docker-настройки для запуска DPI-сервиса, тестовой сети и Linux-only тестов.

## Имена Compose и образов

Compose-конфигурация не привязана к названию репозитория. По умолчанию используются нейтральные локальные имена:

- compose project: `dpi`
- runtime-образ: `dpi:local`
- test-образ: `dpi-test:local`
- client-образ: `dpi-client:local`

Имена можно переопределить через Make-переменные:

```bash
DOCKER_PROJECT=my-dpi DOCKER_IMAGE=my-dpi:dev DOCKER_TEST_IMAGE=my-dpi-test:dev DOCKER_CLIENT_IMAGE=my-dpi-client:dev make docker-build
```

В `docker-compose.yml` намеренно не задан `container_name`: Docker Compose сам формирует имена контейнеров от имени проекта. Так проще запускать несколько окружений параллельно и меньше риск конфликтов в CI.

## Основные команды

Собрать локальные образы:

```bash
make docker-build
```

Запустить тесты внутри Docker:

```bash
make docker-unit
make docker-integration
```

Тестовые цели переиспользуют уже собранные локальные образы. Если изменились `Dockerfile`, `go.mod` или Docker-зависимости, сначала пересоберите образы:

```bash
make docker-build
```

Запустить тестовую топологию `dpi + client + target`:

```bash
make docker-up
```

Остановить и удалить контейнеры и сети compose-проекта:

```bash
make docker-down
```

Посмотреть, сколько места занимают Docker-образы, контейнеры и build cache:

```bash
make docker-disk
```

Очистить build cache:

```bash
make docker-prune-build-cache
```

Удалить dangling-образы после ручных пересборок:

```bash
make docker-prune-dangling
```

## Colima на macOS

На машинах с небольшим SSD лучше задавать лимит диска явно:

```bash
colima start --runtime docker --cpus 2 --memory 2 --disk 12 --root-disk 8
```

Полезные проверки:

```bash
colima list
docker system df -v
du -sh ~/.colima
colima ssh -- df -h / /var/lib/docker
```

После очистки Docker-данных можно выполнить trim внутри VM:

```bash
colima ssh -- sudo fstrim -av
colima stop
```

Colima использует sparse-диск: macOS-файл VM может выглядеть больше, чем текущие Docker-данные внутри VM. Для диагностики ориентируйтесь на `docker system df -v` и `df -h /var/lib/docker` внутри Colima.
