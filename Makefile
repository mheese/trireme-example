PROJECT_NAME := trireme-example
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)
BIN_PATH := /usr/local/bin

init:
	glide install

build_linux:
	CGO_ENABLED=1 go build -a -installsuffix cgo

build: init build_linux
	@echo "Success"

install: build
	  sudo cp trireme-example $(BIN_PATH)/trireme-example

package:
	cp trireme-example docker/trireme-example

docker_build:
	cp trireme-example docker/
	cd docker
	docker \
		build \
		-t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) docker

docker_push: docker_build
	docker \
		push \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)

clean:
	rm -rf vendor
	rm -rf docker/trireme-example
