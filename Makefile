MODE ?= DEBUG

HOST_ARCH := $(shell uname -m)

ifeq ($(HOST_ARCH),x86_64)
  TARGET_GOARCH := amd64
else ifeq ($(HOST_ARCH),arm64)
  TARGET_GOARCH := arm64
else ifeq ($(HOST_ARCH),aarch64)
  TARGET_GOARCH := arm64
else
  TARGET_GOARCH := amd64
endif

ifeq ($(MODE),DEBUG)
  BUILD_TAG := debug
else
  BUILD_TAG := release
endif

SHELL := /usr/bin/env bash

UB_UID := $(shell id -u)
UB_GID := $(shell id -g)

BASE_IMAGE := golang:1.24-bookworm

OUTPUT_DIR := bin

# ──────────────────────────────────────────────────────────────────────────────
#  Development Environment
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: image
image:
	cd dev && sudo docker image build \
		--build-arg BASE_IMAGE=${BASE_IMAGE} \
		--build-arg UB_UID=$(UB_UID) \
		--build-arg UB_GID=$(UB_GID) \
		-t go-prism-dev:202507 .

.PHONY: shell
shell:
	sudo docker container run -it --rm \
		-p 80:80 \
		-p 443:443 \
		-v ./:/work \
		go-prism-dev:202507 bash

# ──────────────────────────────────────────────────────────────────────────────
#  Helper Commands (which can also be used in Development Environment)
# ──────────────────────────────────────────────────────────────────────────────

# Format codes
.PHONY: format
format:
	go -C api fmt ./...
	go -C client fmt ./...
	go -C proxy fmt ./...
	go -C pkg fmt ./...

# Test codes
.PHONY: test
test: export GOTRACEBACK=all
test:
	@set -euo pipefail; \
	for m in pkg proxy; do \
	  echo "==> $$m"; \
	  go -C $$m test -v -race -count=1 -failfast ./...; \
	done

.PHONY: all
all: api client proxy

.PHONY: api client proxy
api:    ; go -C api    build -o ../$(OUTPUT_DIR)/api
client: ; go -C client build -o ../$(OUTPUT_DIR)/client
proxy:  ; go -C proxy  build -tags ${BUILD_TAG} -o ../$(OUTPUT_DIR)/proxy

.PHONY: clean
clean:
	rm -rf $(OUTPUT_DIR)

# ──────────────────────────────────────────────────────────────────────────────
#  Helper Commands
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: install
install:
	mkdir -p ~/.local/bin
	cp ./bin/proxy ~/.local/bin/prism

.PHONY: react
react:
	cd react && npm run build

.PHONY: dev
dev:
	@echo "Current IP addresses:"
	#@hostname -I
	sudo docker compose --env-file ./envs/develop.env up

.PHONY: build/proxy
build/proxy:
	sudo docker compose build proxy

.PHONY: build/client
build/client:
	sudo docker compose build client

.PHONY: build/api
build/api:
	sudo docker compose build api

.PHONY: build
build:
	sudo docker compose --env-file ./envs/develop.env down
	sudo docker image prune -f
	cd react && npm run build
	sudo docker compose --env-file ./envs/develop.env build \
		--build-arg BUILD_TAG=${BUILD_TAG} \
		--build-arg TARGET_GOARCH=${TARGET_GOARCH}
