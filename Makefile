PROJECT_NAME := trireme-example
VERSION := 0.11
GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_DIRTY=$(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)
BIN_PATH := /usr/local/bin

build:
	CGO_ENABLED=1 go build -a -installsuffix cgo \
		-ldflags \
			"-X github.com/aporeto-inc/trireme-example/versions.VERSION=$(VERSION) \
			 -X github.com/aporeto-inc/trireme-example/versions.REVISION=$(GIT_COMMIT)$(GIT_DIRTY)"

install: build
	  sudo cp trireme-example $(BIN_PATH)/trireme-example

package: build
	cp trireme-example docker/trireme-example

docker_build: package
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
