PROJECT_NAME := trireme-example
VERSION_FILE := ./versions/versions.go
VERSION := 0.11
REVISION=$(shell git log -1 --pretty=format:"%H")
BUILD_NUMBER := latest
DOCKER_REGISTRY?=aporeto
DOCKER_IMAGE_NAME?=$(PROJECT_NAME)
DOCKER_IMAGE_TAG?=$(BUILD_NUMBER)
BIN_PATH := /usr/local/bin

codegen:
	echo 'package versions' > $(VERSION_FILE)
	echo '' >> $(VERSION_FILE)
	echo '// VERSION is the version of Trireme-Example' >> $(VERSION_FILE)
	echo 'const VERSION = "$(VERSION)"' >> $(VERSION_FILE)
	echo '' >> $(VERSION_FILE)
	echo '// REVISION is the revision of Trireme-Example' >> $(VERSION_FILE)
	echo 'const REVISION = "$(REVISION)"' >> $(VERSION_FILE)

build: codegen
	CGO_ENABLED=1 go build -a -installsuffix cgo

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
