UB_UID := $(shell id -u)
UB_GID := $(shell id -g)

.PHONY: image
image:
	sudo docker image build \
		--build-arg UB_UID=$(UB_UID) \
		--build-arg UB_GID=$(UB_GID) \
		-t go-dev:202507 .