#!/bin/bash

# Fetch the latest version from GitHub
fetch_latest_version() {
    curl -s https://api.github.com/repos/mehrantsi/high-performance-kv-store/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Set the default version variable
DEFAULT_VERSION=$(fetch_latest_version)
VERSION=${1:-$DEFAULT_VERSION}

# Determine the host system
HOST_OS=$(uname -s)

# Function to get the correct architecture string
get_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64)
            echo "amd64"
            ;;
        aarch64)
            echo "arm64"
            ;;
        *)
            echo "Unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac
}

# Function to wait for SSH to become available
wait_for_ssh() {
    echo "Waiting for SSH to become available..."
    for i in {1..60}; do
        if sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@localhost exit 2>/dev/null; then
            echo "SSH is now available."
            return 0
        fi
        sleep 5
    done
    echo "Timed out waiting for SSH to become available."
    return 1
}

download_and_run_fresh_container() {
    local ARCH=$1
    local VERSION=$2

    echo "Attempting to download and run a fresh container..."

    # Remove existing container if it exists
    docker rm -f hpkv-container 2>/dev/null

    # Remove existing image
    docker rmi "hpkv-image:${VERSION}-${ARCH}" 2>/dev/null

    # Download and load the image from GitHub
    echo "Downloading Docker image..."
    if ! wget "https://github.com/mehrantsi/high-performance-kv-store/releases/download/${VERSION}/hpkv-image-${ARCH}.tar.gz"; then
        echo "Failed to download the image. Please check your internet connection and try again."
        exit 1
    fi
    
    echo "Loading Docker image..."
    if ! docker load < hpkv-image-${ARCH}.tar.gz; then
        echo "Failed to load the Docker image. Exiting."
        exit 1
    fi
    rm hpkv-image-${ARCH}.tar.gz

    # Run the fresh container
    if ! docker run -d --rm \
      --name hpkv-container \
      --privileged \
      --device /dev/loop-control:/dev/loop-control \
      -p 3000:3000 \
      "hpkv-image:${VERSION}-${ARCH}"; then
        echo "Failed to start the fresh container. Exiting."
        exit 1
    fi

    echo "Fresh container started successfully."
}

# Function to check if container is running and healthy
check_container_health() {
    if ! docker ps | grep -q hpkv-container; then
        return 1
    fi
    # Add more health checks if needed
    return 0
}

update_on_linux() {
    local ARCH=$(get_arch)
    
    echo "Checking container health..."
    if ! check_container_health; then
        echo "Container is not running or unhealthy. Attempting to start a fresh container."
        download_and_run_fresh_container $ARCH $VERSION
    fi

    echo "Copying files to container..."
    if ! docker cp kernel/hpkv_module.c hpkv-container:/app/kernel/ || \
       ! docker cp kernel/Makefile hpkv-container:/app/kernel/ || \
       ! docker cp api/server.js hpkv-container:/app/api/ || \
       ! docker cp start.sh hpkv-container:/app/; then
        echo "Failed to copy files to container. Attempting to start a fresh container."
        download_and_run_fresh_container $ARCH $VERSION
        # Try copying files again
        docker cp kernel/hpkv_module.c hpkv-container:/app/kernel/
        docker cp kernel/Makefile hpkv-container:/app/kernel/
        docker cp api/server.js hpkv-container:/app/api/
        docker cp start.sh hpkv-container:/app/
    fi

    echo "Building and updating in container..."
    if ! docker exec hpkv-container /bin/bash -c "cd /app/kernel && make clean && make && mv hpkv_module.ko hpkv_module_${ARCH}.ko" || \
       ! docker exec hpkv-container /bin/bash -c "cd /app/api && npm install"; then
        echo "Failed to build or update in container. Attempting to start a fresh container."
        download_and_run_fresh_container $ARCH $VERSION
        # Try building and updating again
        docker exec hpkv-container /bin/bash -c "cd /app/kernel && make clean && make && mv hpkv_module.ko hpkv_module_${ARCH}.ko"
        docker exec hpkv-container /bin/bash -c "cd /app/api && npm install"
    fi

    # Commit changes to a new image
    if ! docker commit hpkv-container "hpkv-image:${VERSION}-${ARCH}"; then
        echo "Failed to commit changes. Exiting."
        exit 1
    fi

    # Remove old images
    OLD_IMAGES=$(docker images -q "hpkv-image:${VERSION}-${ARCH}")
    for img in $OLD_IMAGES; do
        if [ "$img" != "$(docker images -q hpkv-image:${VERSION}-${ARCH})" ]; then
            docker rmi -f $img || true
        fi
    done
    # Remove any dangling images
    docker image prune -f
    
    docker stop hpkv-container || true
    echo "Waiting for container to stop..."
    while docker ps | grep -q hpkv-container; do
        sleep 1
    done

    # Check and remove the kernel module
    echo "Checking if the kernel module is still running..."
    if lsmod | grep -q hpkv_module; then
        echo "Removing hpkv_module..."
        sudo rmmod hpkv_module || true
    else
        echo "hpkv_module is not running."
    fi

    docker rm hpkv-container || true
    echo "Waiting for container to be removed..."
    while docker ps -a | grep -q hpkv-container; do
        sleep 1
    done
    docker run -d --rm \
      --name hpkv-container \
      --privileged \
      --device /dev/loop-control:/dev/loop-control \
      -p 3000:3000 \
      "hpkv-image:${VERSION}-${ARCH}"
    echo "New container started."
}

update_in_qemu() {
    echo "Checking if QEMU process is running..."
    if pgrep -f "qemu-system-x86_64.*ubuntu-vm-disk.qcow2" > /dev/null; then
        echo "QEMU process found."
    else
        echo "QEMU process not found. Make sure the VM is running."
        exit 1
    fi

    echo "Checking if port 2222 is open..."
    if nc -z localhost 2222; then
        echo "Port 2222 is open."
    else
        echo "Port 2222 is not open. Make sure QEMU is forwarding this port."
        exit 1
    fi

    if ! wait_for_ssh; then
        echo "Failed to connect to QEMU VM. Exiting."
        exit 1
    fi

    echo "Copying files to QEMU VM..."
    sshpass -p "ubuntu" scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kernel/hpkv_module.c kernel/Makefile api/server.js start.sh ubuntu@localhost:~

    echo "Building kernel module in QEMU VM..."
    sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no ubuntu@localhost << EOF
        mkdir -p ~/kernel_build
        mv hpkv_module.c Makefile ~/kernel_build/
        cd ~/kernel_build
        make clean
        make
        if [ ! -f hpkv_module.ko ]; then
            echo "Failed to build kernel module"
            exit 1
        fi
        mv hpkv_module.ko hpkv_module_x86_64.ko

        # Function to check available space
        check_space() {
            available_space=\$(df / | awk 'NR==2 {print \$4}')
            echo \$available_space
        }

        # Function to perform thorough cleanup
        thorough_cleanup() {
            echo "Performing thorough cleanup..."
            
            # Clean up /tmp
            sudo find /tmp -type f -atime +7 -delete

            # Clean up user's home directory
            rm -rf ~/.cache/*

            # Clean up Docker-related directories
            sudo du -sh /var/lib/docker
            
            # Perform initial cleanup
            echo "Performing initial cleanup..."
            if [ -n "\$LATEST_IMAGE" ]; then
                # Remove all images except the latest one
                sudo docker images --format "{{.Repository}}:{{.Tag}}" | grep "hpkv-image:${VERSION}-amd64" | grep -v "\$LATEST_IMAGE" | xargs -r sudo docker rmi -f
                
                # Prune everything except the latest image
                LATEST_IMAGE_ID=\$(sudo docker images --format "{{.ID}}" "\$LATEST_IMAGE")
                sudo docker system prune -af --volumes --filter "until=24h" --filter "label!=com.docker.image.id=\$LATEST_IMAGE_ID"
            else
                # If no latest image, perform a full prune
                sudo docker system prune -af --volumes
            fi
            
            sudo rm -rf /var/lib/docker/tmp/*
            sudo rm -rf /var/lib/docker/builder/*/
            
            # Clean up old log files
            sudo find /var/log -type f -name "*.log" -mtime +30 -delete
            sudo find /var/log -type f -name "*.gz" -mtime +30 -delete

            # Clean up old kernels
            sudo apt-get autoremove --purge -y

            # Clean up apt cache
            sudo apt-get clean

            echo "Thorough cleanup completed."
        }

        # Stop the container if it's running
        if sudo docker ps | grep -q hpkv-container; then
            echo "Stopping existing container..."
            sudo docker stop hpkv-container
            sudo docker rm hpkv-container
        fi

        # Identify the latest image
        LATEST_IMAGE=\$(sudo docker images --format "{{.Repository}}:{{.Tag}}" | grep "hpkv-image:${VERSION}-amd64" | head -n 1)

        # Check available space after initial cleanup
        initial_space=\$(check_space)
        echo "Available space after initial cleanup: \$initial_space KB"

        # If available space is less than 2GB, perform thorough cleanup
        if [ \$initial_space -lt 2097152 ]; then
            thorough_cleanup
            
            # Check space again after thorough cleanup
            final_space=\$(check_space)
            echo "Available space after thorough cleanup: \$final_space KB"
            
            # If still not enough space, exit with an error
            if [ \$final_space -lt 2097152 ]; then
                echo "Error: Not enough space available even after thorough cleanup."
                exit 1
            fi
        fi

        # Start a fresh container
        if [ -z "\$LATEST_IMAGE" ]; then
            echo "No existing image found. Downloading a fresh one..."
            wget "https://github.com/mehrantsi/high-performance-kv-store/releases/download/${VERSION}/hpkv-image-amd64.tar.gz"
            sudo docker load < hpkv-image-amd64.tar.gz
            rm hpkv-image-amd64.tar.gz
            LATEST_IMAGE="hpkv-image:${VERSION}-amd64"
        fi

        echo "Starting a fresh container..."
        sudo docker run -d --rm \
          --name hpkv-container \
          --privileged \
          --device /dev/loop-control:/dev/loop-control \
          -p 3000:3000 \
          "\$LATEST_IMAGE"

        # Copy files and update container
        sudo docker cp hpkv_module_x86_64.ko hpkv-container:/app/kernel/
        sudo docker cp ~/server.js hpkv-container:/app/api/
        sudo docker cp ~/start.sh hpkv-container:/app/
        sudo docker exec hpkv-container chmod +x /app/start.sh
        sudo docker exec hpkv-container /bin/bash -c "cd /app/api && npm install"

        # Commit changes to a new image
        sudo docker commit hpkv-container "\$LATEST_IMAGE"

        # Restart the container with the updated image
        sudo docker stop hpkv-container
        sudo docker rm hpkv-container

        # Check and remove the kernel module
        echo "Checking if the kernel module is still running..."
        if lsmod | grep -q hpkv_module; then
            echo "Removing hpkv_module..."
            sudo rmmod hpkv_module || true
        else
            echo "hpkv_module is not running."
        fi

        # Wait for the container to be fully removed
        echo "Waiting for the old container to be fully removed..."
        for i in {1..30}; do
            if ! sudo docker ps -a | grep -q hpkv-container; then
                echo "Old container has been removed."
                break
            fi
            if [ $i -eq 30 ]; then
                echo "Timeout waiting for the old container to be removed."
                exit 1
            fi
            sleep 1
        done

        if sudo docker run -d --rm \
          --name hpkv-container \
          --privileged \
          --device /dev/loop-control:/dev/loop-control \
          -p 3000:3000 \
          "\$LATEST_IMAGE"; then
            echo "New container started with updated image."
            
            # Wait for the container to be fully up and running
            echo "Waiting for the new container to be ready..."
            for i in {1..30}; do
                if sudo docker exec hpkv-container /bin/bash -c "exit 0" 2>/dev/null; then
                    echo "New container is ready."
                    break
                fi
                if [ \$i -eq 30 ]; then
                    echo "Timeout waiting for the new container to be ready."
                    exit 1
                fi
                sleep 1
            done

            # Final cleanup only if the new container started successfully
            echo "Performing final cleanup..."
            sudo docker system prune -af --volumes

            # Check available disk space again
            echo "Checking available disk space after cleanup..."
            df -h /
        else
            echo "Failed to start the new container. Skipping final cleanup."
            exit 1
        fi
EOF
}

# Main execution
if [ "$HOST_OS" = "Darwin" ]; then
    echo "macOS detected. Updating in QEMU VM..."
    update_in_qemu
elif [ "$HOST_OS" = "Linux" ]; then
    echo "Linux detected. Updating directly in container..."
    update_on_linux
else
    echo "Unsupported operating system: $HOST_OS"
    exit 1
fi

echo "Update complete. New container is running with updated code."