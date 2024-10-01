#!/bin/bash

# Set the version variable
VERSION="v1.2-docker"

# Check if the image already exists
if docker image inspect "hpkv-image:${VERSION}" &> /dev/null; then
    echo "Docker image hpkv-image:${VERSION} already exists. Skipping download."
else
    # Download the Docker image
    echo "Downloading Docker image..."
    wget "https://github.com/mehrantsi/high-performance-kv-store/releases/download/${VERSION}/hpkv-image-arm64.tar"

    # Load the Docker image
    echo "Loading Docker image..."
    docker load < hpkv-image-arm64.tar

    # Clean up the downloaded tar file
    rm hpkv-image-arm64.tar
fi

# Run the Docker container
echo "Running Docker container..."
docker run --rm \
  --name hpkv-container \
  --privileged \
  --device /dev/loop-control:/dev/loop-control \
  -p 4242:80 \
  "hpkv-image-arm64:${VERSION}"

# The container will be automatically removed when it exits due to the --rm flag

echo "Container has exited and been removed."