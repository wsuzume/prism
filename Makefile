SHELL := /usr/bin/env bash

UB_UID := $(shell id -u)
UB_GID := $(shell id -g)

.PHONY: image
image:
	cd dev && sudo docker image build \
		--build-arg UB_UID=$(UB_UID) \
		--build-arg UB_GID=$(UB_GID) \
		-t go-dev:202507 .

.PHONY: shell
shell:
	sudo docker container run -it --rm \
		-p 8080:8080 \
		-v ./:/work \
		go-dev:202507 bash

.PHONY: dev
dev:
	@echo "Current IP addresses:"
	@hostname -I
	sudo docker compose --env-file ./envs/develop.env up

.PHONY: format
format:
	go -C api fmt ./...
	go -C client fmt ./...
	go -C proxy fmt ./...
	go -C pkg fmt ./...

.PHONY: test
test: export GOTRACEBACK=all
test:
	@set -euo pipefail; \
	for m in pkg proxy; do \
	  echo "==> $$m"; \
	  go -C $$m test -v -race -count=1 -failfast ./...; \
	done

BIN=bin
.PHONY: api client proxy react all clean
api:    ; go -C api    build -o ../$(BIN)/api
client: ; go -C client build -o ../$(BIN)/client
proxy:  ; go -C proxy  build -o ../$(BIN)/proxy
react:  ; cd react && npm run build
all: api client proxy
clean: ; rm -rf $(BIN)

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
	sudo docker compose --env-file ./envs/develop.env build

.PHONY: run
run:
	cd deploy && make run

.PHONY: push
push:
	mkdir -p deploy
	cp ./docker-compose.yml deploy
	cp -r ./envs deploy
	sudo docker save fl-client:latest -o deploy/fl-client.tar
	sudo docker save fl-proxy:latest -o deploy/fl-proxy.tar
	sudo docker save fl-api:latest -o deploy/fl-api.tar
	sudo chown -R `id -un`:`id -gn` deploy
	scp -r deploy web:~/