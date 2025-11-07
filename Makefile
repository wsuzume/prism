UNAME := $(shell id -un)
UID := $(shell id -u)
GID := $(shell id -g)

BASE_IMAGE := golang:1.24-bookworm

OUTPUT_DIR := bin

# ──────────────────────────────────────────────────────────────────────────────
#  Development Environment
# ──────────────────────────────────────────────────────────────────────────────

DEV_IMAGE_TAG := 202507

.PHONY: image
image:
	sudo docker image build \
		--build-arg BASE_IMAGE=${BASE_IMAGE} \
		--build-arg UNAME=$(UNAME) \
		--build-arg UID=$(UID) \
		--build-arg GID=$(GID) \
		-f ./dev/Dockerfile \
		-t go-prism-dev:${DEV_IMAGE_TAG} .

.PHONY: shell
shell:
	@if ! sudo docker ps -a --format '{{.Names}}' | grep -q '^go-prism-dev$$'; then \
		echo "Creating new container..."; \
		sudo docker run -it --name go-prism-dev -v ./:/work go-prism-dev:${DEV_IMAGE_TAG} bash; \
	else \
		if [ "$$(sudo docker inspect -f '{{.State.Running}}' go-prism-dev)" = "true" ]; then \
			echo "Entering existing container..."; \
			sudo docker exec -it go-prism-dev bash; \
		else \
			echo "Restarting existing container..."; \
			sudo docker start -ai go-prism-dev; \
		fi \
	fi

.PHONY: reset
reset:
	sudo docker container rm go-prism-dev

# ──────────────────────────────────────────────────────────────────────────────
#  Repository Management
# ──────────────────────────────────────────────────────────────────────────────

.PHONY: init
init:
	rm -f go.work*
	go work init
	go work use ./pkg
	go work use ./prism

# ──────────────────────────────────────────────────────────────────────────────
#  Command Line Tool
# ──────────────────────────────────────────────────────────────────────────────

PRISM_SRCS := $(shell find ./prism ./pkg -type f -name '*.go')

prism: $(PRISM_SRCS)
	go -C ./prism build -o ../${OUTPUT_DIR}/prism

.PHONY: format/prism
format/prism:
	go -C ./prism fmt ./...

.PHONY: install
install:
	mkdir -p ~/.local/bin
	cp ./bin/prism ~/.local/bin


.PHONY: test/pkg
test/pkg:
	go -C ./pkg test -v -race -count=1 -failfast ./...