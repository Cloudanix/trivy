# Cloudanix build wrapper for the image-scanner binary, packaged as image-scanner.
#
#   make build                 build the image-scanner binary into ./bin
#   make test | vet | lint     run tests / vet / lint
#   make docker                build image and load into the local daemon
#   make docker-push           build image and push to the registry
#   make docker-multi          build amd64+arm64 and push
#   append LATEST=1 to also tag/push the "latest" tag
#
# docker/docker-push build for PLATFORMS (default linux/amd64). A multi-arch
# image can only be pushed (buildx cannot --load one), so docker-multi always
# pushes. docker loads locally, docker-push pushes; they share one recipe via
# OUT.
PLATFORMS ?= linux/arm64
LATEST ?=

# LATEST=1 also tags/pushes the "latest" image tag.
LATEST_FLAG := $(if $(LATEST),--latest,)

.PHONY: build test test_coverage test-integration vet lint tidy dep hooks docker docker-push docker-multi help

export GOEXPERIMENT = jsonv2

build:
	@mkdir -p bin
	go build -o bin/image-scanner ./cmd/image-scanner

test:
	go test ./...

test_coverage:
	go test ./... -coverprofile=coverage.out

test-integration:
	go test -tags integration ./...

vet:
	go vet ./...

lint:
	golangci-lint run --enable-all

tidy:
	go mod tidy

dep:
	go mod download

hooks:
	git config core.hooksPath .githooks

# docker loads locally, docker-push pushes; they share one recipe via OUT.
docker:      OUT := --load
docker-push: OUT := --push
docker docker-push:
	./scripts/build.sh --platforms $(PLATFORMS) $(OUT) $(LATEST_FLAG)

docker-multi:
	./scripts/build.sh --platforms linux/amd64,linux/arm64 --load --push $(LATEST_FLAG)

help:
	@echo "Targets: build test test_coverage test-integration vet lint tidy dep hooks docker docker-push docker-multi"
	@echo "PLATFORMS=... overrides arch for docker/docker-push"
	@echo "LATEST=1 also tags/pushes the 'latest' tag on docker/docker-push/docker-multi"
