#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./build.sh [OPTIONS]
This script generates a Docker image for the image-scanner service.

Options:
  --tag TAG              Image tag (default: git describe, or "0.0.0-dev")
  --push                 Push images to registry (default: false)
  --latest               Also tag/push "latest" (default: false)
  -h, --help             Show this help message

Examples:
  ./build.sh --tag v1.2.3
  ./build.sh --tag v1.2.3 --push
  ./build.sh --tag v1.2.3 --latest --push
'
    exit
fi

main() {
	# Default values
	CURRENT_TAG="v$(git describe --tags --always --dirty="-dirty" 2>/dev/null || echo "0.0.0-dev")"
	IMAGE_TAG="$CURRENT_TAG"
	PLATFORMS="linux/amd64"
	PUSH_IMAGES="false"
	PUSH_LATEST="false"

	REGISTRY="cloudanix"

	IMAGE_NAME="image-scanner"

	# Parse command line arguments
	while [[ $# -gt 0 ]]; do
		case $1 in
			--latest)
				PUSH_LATEST="true"
				shift
				;;
			--tag)
				IMAGE_TAG="$2"
				shift 2
				;;
			--push)
				PUSH_IMAGES="true"
				shift
				;;
			*)
				echo "Unknown option: $1"
				echo "Use --help for usage information"
				exit 1
				;;
		esac
	done

	export IMAGE_TAG
	FULL_IMAGE_NAME="$REGISTRY/$IMAGE_NAME"

	echo "Configuration:"
	echo "  Image: $FULL_IMAGE_NAME:$IMAGE_TAG"
	echo "  Platforms: $PLATFORMS"
	echo "  Push to latest: $PUSH_LATEST"
	echo "  Push images: $PUSH_IMAGES"
	echo ""

	# Login to Docker registry if credentials are available
	if [[ "$PUSH_IMAGES" == "true" && -n "${CDX_DOCKER_PASSWORD:-}" && -n "${CDX_DOCKER_USERNAME:-}" ]]; then
		echo "Logging into Docker registry..."
		echo "$CDX_DOCKER_PASSWORD" | docker login -u "$CDX_DOCKER_USERNAME" --password-stdin
	elif [[ "$PUSH_IMAGES" == "true" ]]; then
		echo "Warning: Docker credentials not found. Assuming already logged in or using local registry."
	fi

	echo "Tidying Go modules..."
	go mod tidy

	echo "Building Image Scanner binary..."
	GOOS="linux" GOARCH="amd64" GOEXPERIMENT=jsonv2 go build -o "${IMAGE_NAME}" "./cmd/$IMAGE_NAME"

	BUILD_TAGS=(-t "$FULL_IMAGE_NAME:$IMAGE_TAG")
	if [[ "$PUSH_LATEST" == "true" ]]; then
		BUILD_TAGS+=(-t "$FULL_IMAGE_NAME:latest")
	fi

	# Build and optionally push the main tag
	echo "Building $FULL_IMAGE_NAME:$IMAGE_TAG..."

	BUILD_CMD=(docker buildx build --platform "$PLATFORMS" --progress=plain)
	if [[ "$PUSH_IMAGES" == "true" ]]; then
		BUILD_CMD+=(--push)
	else
		BUILD_CMD+=(--load)
	fi

	mkdir -p ./scripts/logs

	"${BUILD_CMD[@]}" "${BUILD_TAGS[@]}" \
		-f "./cmd/$IMAGE_NAME/Dockerfile" \
		--build-arg "SVC_VERSION=$IMAGE_TAG" \
		--progress=plain \
		. 2>&1 | tee "./scripts/logs/$IMAGE_NAME-$IMAGE_TAG.log"

	echo "Build completed successfully!"
	echo "Built image: $FULL_IMAGE_NAME:$IMAGE_TAG"
	if [[ "$PUSH_LATEST" == "true" ]]; then
		echo "Built image: $FULL_IMAGE_NAME:latest"
	fi
}

main "$@"
