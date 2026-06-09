# Makefile для awgproxy. Под Windows запускать через GNU make (git-bash/WSL/scoop).

BIN        := awgproxy
PKG        := ./cmd/awgproxy
MODULE     := github.com/glebov/awg-proxy-go

# Все артефакты сборки складываем сюда.
DIST       := dist

# Версия/сборка — подставляются в buildinfo и в имя docker-образа.
# BUILD по умолчанию читается из файла-счётчика .build; docker/save его инкрементят.
# Ручное значение: make save BUILD=200
VERSION    ?= 0.0.1
BUILD      ?= $(shell cat .build 2>/dev/null || echo 0000)
TARGETARCH ?= arm64
# Платформа для buildx (для armv7 переопределяется на linux/arm/v7 в save-arm).
PLATFORM   ?= linux/$(TARGETARCH)
VARIANT    ?=
NAME       := $(BIN)-$(VERSION)-$(BUILD)-$(TARGETARCH)
IMAGE      ?= $(BIN):$(VERSION)-$(BUILD)-$(TARGETARCH)
ARCHIVE    ?= $(DIST)/$(NAME).tar.gz

LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Build=$(BUILD)

# Расширение бинаря под Windows.
ifeq ($(OS),Windows_NT)
	EXE := .exe
else
	EXE :=
endif

.DEFAULT_GOAL := help

## help: показать список команд
help:
	@echo "awgproxy — команды:"
	@awk 'BEGIN{FS=": "} /^## [a-z0-9-]+:/ {sub(/^## /,""); printf "  make %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## run: запустить локально (go run)
run:
	go run -ldflags="$(LDFLAGS)" $(PKG)

## build: собрать локальный бинарь
build: | $(DIST)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BIN)$(EXE) $(PKG)

## build-router: собрать статический бинарь под архитектуру роутера (TARGETARCH)
build-router: | $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGETARCH) \
		go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BIN)-$(TARGETARCH) $(PKG)

# Каталог dist создаётся под все таргеты, которые в него пишут.
$(DIST):
	mkdir -p $(DIST)

## build-arm64: бинарь под arm64 (современные MikroTik)
build-arm64:
	$(MAKE) build-router TARGETARCH=arm64

## build-arm: бинарь под arm (старые MikroTik)
build-arm:
	$(MAKE) build-router TARGETARCH=arm

## build-amd64: бинарь под amd64 (CHR/x86, RB5009)
build-amd64:
	$(MAKE) build-router TARGETARCH=amd64

## build-all: бинари под все архитектуры
build-all: build-arm64 build-arm build-amd64

## test: прогнать тесты
test:
	go test ./...

## cover: тесты с покрытием
cover: | $(DIST)
	go test -cover -coverprofile=$(DIST)/coverage.out ./...
	go tool cover -func=$(DIST)/coverage.out

## vet: статический анализ
vet:
	go vet ./...

## fmt: отформатировать код
fmt:
	gofmt -w .

## lint: golangci-lint (если установлен)
lint:
	golangci-lint run ./...

## tidy: привести в порядок go.mod/go.sum
tidy:
	go mod tidy

## check: быстрая проверка перед коммитом (vet + test)
check: vet test

## bump: увеличить номер сборки в .build (или зафиксировать заданный BUILD=)
bump:
ifeq ($(origin BUILD),command line)
	@printf '%s\n' "$(BUILD)" > .build
	@echo "build $(BUILD) (задан вручную)"
else
	@n=$$(cat .build 2>/dev/null || echo 0); n=$$((10#$$n + 1)); \
		printf '%04d\n' "$$n" > .build; echo "build $$(cat .build)"
endif

## docker: собрать docker-образ под роутер (инкремент сборки, загрузка в локальный docker)
docker: bump
	@$(MAKE) --no-print-directory _docker

_docker:
	docker buildx build \
		--platform $(PLATFORM) \
		--provenance=false \
		--build-arg TARGETARCH=$(TARGETARCH) \
		--build-arg TARGETVARIANT=$(VARIANT) \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD=$(BUILD) \
		-t $(IMAGE) --load .

## save: собрать и выгрузить образ в .tar.gz (инкремент сборки, docker-archive для RouterOS)
save: bump
	@$(MAKE) --no-print-directory _save

_save: | $(DIST)
	docker buildx build \
		--platform $(PLATFORM) \
		--provenance=false \
		--build-arg TARGETARCH=$(TARGETARCH) \
		--build-arg TARGETVARIANT=$(VARIANT) \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD=$(BUILD) \
		-t $(IMAGE) \
		--output type=docker,dest=$(DIST)/$(NAME).oci.tar,oci-mediatypes=false,compression=uncompressed .
	sh scripts/repack-docker-archive.sh $(DIST)/$(NAME).oci.tar $(DIST)/$(NAME).tar
	rm -f $(DIST)/$(NAME).oci.tar
	gzip -9 -f $(DIST)/$(NAME).tar
	@echo "saved -> $(ARCHIVE)"

## save-arm64: образ + архив под arm64
save-arm64:
	@$(MAKE) --no-print-directory save TARGETARCH=arm64

## save-arm: образ + архив под armv7
save-arm:
	@$(MAKE) --no-print-directory save TARGETARCH=arm PLATFORM=linux/arm/v7 VARIANT=v7

## save-amd64: образ + архив под amd64
save-amd64:
	@$(MAKE) --no-print-directory save TARGETARCH=amd64

## save-all: образы + архивы под все архитектуры (один общий номер сборки)
save-all: bump
	@$(MAKE) --no-print-directory _save TARGETARCH=arm64
	@$(MAKE) --no-print-directory _save TARGETARCH=arm PLATFORM=linux/arm/v7 VARIANT=v7
	@$(MAKE) --no-print-directory _save TARGETARCH=amd64

## clean: удалить артефакты сборки
clean:
	rm -rf $(DIST)
	rm -f $(BIN) $(BIN)$(EXE) $(BIN)-* $(BIN)-*.tar.gz coverage.out

.PHONY: help run build build-router build-arm64 build-arm build-amd64 build-all \
	test cover vet fmt lint tidy check bump docker _docker save _save \
	save-arm64 save-arm save-amd64 save-all clean
