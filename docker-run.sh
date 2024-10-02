#!/bin/bash

# Set the version variable
VERSION="v1.2-docker"

# Determine the system architecture
ARCH=$(uname -m)
case ${ARCH} in
    x86_64)
        DOCKER_ARCH="amd64"
        ;;
    aarch64)
        DOCKER_ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

# Check if the image already exists
if docker image inspect "hpkv-image:${VERSION}-${DOCKER_ARCH}" &> /dev/null; then
    echo "Docker image hpkv-image:${VERSION}-${DOCKER_ARCH} already exists. Skipping download."
else
    # Download the Docker image
    echo "Downloading Docker image..."
    wget "https://github.com/mehrantsi/high-performance-kv-store/releases/download/${VERSION}/hpkv-image-${DOCKER_ARCH}.tar.gz"

    # Load the Docker image
    echo "Loading Docker image..."
    docker load < hpkv-image-${DOCKER_ARCH}.tar.gz

    # Clean up the downloaded tar.gz file
    rm hpkv-image-${DOCKER_ARCH}.tar.gz
fi

# Run the Docker container
echo "Running Docker container..."
docker run --rm \
  --name hpkv-container \
  --privileged \
  --device /dev/loop-control:/dev/loop-control \
  -p 3000:3000 \
  "hpkv-image:${VERSION}-${DOCKER_ARCH}"

# The container will be automatically removed when it exits due to the --rm flag

echo "Container has exited and been removed."