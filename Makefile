GO ?= go
CONFIG ?= configs/dpi.toml
DOCKER_COMPOSE ?= docker-compose
DOCKER_PROJECT ?= dpi
DOCKER_IMAGE ?= dpi:local
DOCKER_TEST_IMAGE ?= dpi-test:local
DOCKER_CLIENT_IMAGE ?= dpi-client:local
DOCKER_ENV = COMPOSE_PROJECT_NAME=$(DOCKER_PROJECT) DPI_IMAGE=$(DOCKER_IMAGE) DPI_TEST_IMAGE=$(DOCKER_TEST_IMAGE) DPI_CLIENT_IMAGE=$(DOCKER_CLIENT_IMAGE)

.PHONY: build fmt run test test-integration docker-build docker-ensure-images docker-ensure-topology-images docker-unit docker-integration docker-up docker-down docker-disk docker-prune-build-cache docker-prune-dangling

build:
	$(GO) build ./cmd/dpi

fmt:
	$(GO) fmt ./...

run:
	$(GO) run ./cmd/dpi -config $(CONFIG)

test:
	$(GO) test ./... -count=1

test-integration:
	$(GO) test -tags=integration ./tests/integration -count=1 -v

docker-build:
	$(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml build dpi test client

docker-ensure-images:
	docker image inspect $(DOCKER_IMAGE) $(DOCKER_TEST_IMAGE) >/dev/null 2>&1 || $(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml build dpi test

docker-ensure-topology-images:
	docker image inspect $(DOCKER_IMAGE) $(DOCKER_CLIENT_IMAGE) >/dev/null 2>&1 || $(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml build dpi client

docker-unit: docker-ensure-images
	$(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml run --rm --pull never test

docker-integration: docker-ensure-images
	$(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml run --rm --pull never integration

docker-up: docker-ensure-topology-images
	$(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml up dpi client target

docker-down:
	$(DOCKER_ENV) $(DOCKER_COMPOSE) -f docker/docker-compose.yml down --remove-orphans

docker-disk:
	docker system df -v

docker-prune-build-cache:
	docker builder prune -f

docker-prune-dangling:
	docker image prune -f
