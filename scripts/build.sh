#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./build.sh arg-one arg-two
This script would generate a docker image for the image-scanner.'
    exit
fi

main() {
    IMAGE_OWNER="cloudanix"
    IMAGE_NAME="image-scanner"
    RUNTIME_IMAGE_NAME="image-runtime-scanner"

    IMAGE_TAG=$(git describe --tags --always --dirty="-dirty" 2>/dev/null || echo "0.0.0-dev")
    RUNTIME_IMAGE_TAG="$IMAGE_TAG"

    echo "IMAGE_TAG: $IMAGE_TAG"
    echo "RUNTIME_IMAGE_TAG: $RUNTIME_IMAGE_TAG"

    go mod tidy

    echo "$CDX_DOCKER_PASSWORD" | docker login -u "$CDX_DOCKER_USERNAME" --password-stdin

    echo "Building Image Scanner Binary"
    GOOS="linux" GOARCH="amd64" GOEXPERIMENT=jsonv2 go build -o "$IMAGE_NAME" "./cmd/$IMAGE_NAME"

    echo "Build Docker Image to support linux/amd64 platform: $IMAGE_NAME:$IMAGE_TAG"

    docker buildx build --push --platform linux/arm64,linux/amd64 -t "$IMAGE_OWNER/$IMAGE_NAME:$IMAGE_TAG" -f "./cmd/$IMAGE_NAME/Dockerfile" . &> "./scripts/image-scanner-$IMAGE_TAG.log"

    # docker push "$IMAGE_OWNER/$IMAGE_NAME:$IMAGE_TAG"

    # echo "Build Docker Image to support linux/amd64 platform: $IMAGE_NAME:latest"
    # docker build --load --platform linux/amd64 -t "$IMAGE_OWNER/$IMAGE_NAME:latest" -f "./cmd/$IMAGE_NAME/Dockerfile" . &> "./scripts/image-scanner-latest.log"

    # docker push "$IMAGE_OWNER/$IMAGE_NAME:latest"

    # echo "Building Image Runtime Scanner Binary"
    # GOOS="linux" GOARCH="amd64" GOEXPERIMENT=jsonv2 go build -o "$RUNTIME_IMAGE_NAME" "./cmd/$RUNTIME_IMAGE_NAME"

    # echo "Build Docker Image to support linux/amd64 platform: $RUNTIME_IMAGE_NAME:$RUNTIME_IMAGE_TAG"
    # docker build --load --platform linux/amd64 -t "$IMAGE_OWNER/$RUNTIME_IMAGE_NAME:$RUNTIME_IMAGE_TAG" -f "./cmd/$RUNTIME_IMAGE_NAME/Dockerfile" . &> "./scripts/image-runtime-scanner-$RUNTIME_IMAGE_TAG.log"

    # docker push "$IMAGE_OWNER/$RUNTIME_IMAGE_NAME:$RUNTIME_IMAGE_TAG"

    # echo "Build Docker Image to support linux/amd64 platform: $RUNTIME_IMAGE_NAME:latest"
    # docker build --load --platform linux/amd64 -t "$IMAGE_OWNER/$RUNTIME_IMAGE_NAME:latest" -f "./cmd/$RUNTIME_IMAGE_NAME/Dockerfile" . &> "./scripts/image-runtime-scanner-latest.log"

    # docker push "$IMAGE_OWNER/$RUNTIME_IMAGE_NAME:latest"

    unset IMAGE_OWNER IMAGE_NAME IMAGE_TAG RUNTIME_IMAGE_NAME RUNTIME_IMAGE_TAG GOOS GOARCH
}

main "$@"
