#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: ./build.sh [OPTIONS]
This script builds the image-scanner binary and packages it into the image-scanner Docker image.

Options:
  --tag TAG              Image tag (default: git describe, or "0.0.0-dev")
  --platforms PLATFORMS  Target platform(s), comma-separated (default: linux/amd64)
  --push                 Push image to registry (default: false)
  --load                 Load image into the local Docker daemon (default when not pushing)
  --latest               Also tag/push "latest" (default: false)
  -h, --help             Show this help message

Examples:
  ./build.sh --tag v1.2.3
  ./build.sh --tag v1.2.3 --push
  ./build.sh --platforms linux/amd64,linux/arm64 --push --latest
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
			--platforms)
				PLATFORMS="$2"
				shift 2
				;;
			--push)
				PUSH_IMAGES="true"
				shift
				;;
			--load)
				PUSH_IMAGES="false"
				shift
				;;
			*)
				echo "Unknown option: $1"
				echo "Use --help for usage information"
				exit 1
				;;
		esac
	done

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

	mkdir -p ./scripts/logs

	IFS=',' read -ra PLATFORM_LIST <<< "$PLATFORMS"

	if [[ ${#PLATFORM_LIST[@]} -eq 1 ]]; then
		build_one "${PLATFORM_LIST[0]}" "$FULL_IMAGE_NAME:$IMAGE_TAG"
		if [[ "$PUSH_LATEST" == "true" ]]; then
			build_one "${PLATFORM_LIST[0]}" "$FULL_IMAGE_NAME:latest"
		fi
	else
		# cmd/image-scanner/Dockerfile has no ARG TARGETPLATFORM branch, so one
		# buildx call can only bake a single arch's binary. Build+push each
		# platform to its own arch-suffixed tag, then stitch them into one
		# manifest list with `imagetools create`.
		if [[ "$PUSH_IMAGES" != "true" ]]; then
			echo "Multiple platforms require --push (buildx cannot --load a multi-arch manifest)."
			exit 1
		fi
		arch_tags=()
		for platform in "${PLATFORM_LIST[@]}"; do
			arch_tag="$FULL_IMAGE_NAME:$IMAGE_TAG-${platform##*/}"
			build_one "$platform" "$arch_tag"
			arch_tags+=("$arch_tag")
		done
		docker buildx imagetools create -t "$FULL_IMAGE_NAME:$IMAGE_TAG" "${arch_tags[@]}"
		if [[ "$PUSH_LATEST" == "true" ]]; then
			docker buildx imagetools create -t "$FULL_IMAGE_NAME:latest" "${arch_tags[@]}"
		fi
	fi

	echo "Build completed successfully!"
	echo "Built image: $FULL_IMAGE_NAME:$IMAGE_TAG"
	if [[ "$PUSH_LATEST" == "true" ]]; then
		echo "Built image: $FULL_IMAGE_NAME:latest"
	fi
}

# Cross-compile the binary for one platform and buildx-build+tag it.
build_one() {
	local platform="$1" tag="$2"
	local goos="${platform%%/*}"
	local goarch="${platform##*/}"
	local ctx_dir
	ctx_dir="$(mktemp -d)"

	echo "Building $IMAGE_NAME binary for $platform..."
	GOOS="$goos" GOARCH="$goarch" GOEXPERIMENT=jsonv2 go build -o "$ctx_dir/$IMAGE_NAME" "./cmd/$IMAGE_NAME"
	cp "cmd/$IMAGE_NAME/Dockerfile" "$ctx_dir/Dockerfile"
	cp -r contrib "$ctx_dir/contrib"

	local build_cmd=(docker buildx build --platform "$platform" --progress=plain -t "$tag")
	if [[ "$PUSH_IMAGES" == "true" ]]; then
		build_cmd+=(--push)
	else
		build_cmd+=(--load)
	fi

	"${build_cmd[@]}" -f "$ctx_dir/Dockerfile" "$ctx_dir" 2>&1 | tee -a "./scripts/logs/$IMAGE_NAME-$IMAGE_TAG.log"

	rm -rf "$ctx_dir"
}

main "$@"
