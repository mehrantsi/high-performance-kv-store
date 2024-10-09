#!/bin/bash

# Fetch the latest version from GitHub
fetch_latest_version() {
    curl -s https://api.github.com/repos/mehrantsi/high-performance-kv-store/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Set the default version variable
DEFAULT_VERSION=$(fetch_latest_version)
CLEAN_START=false
DEV_MODE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean-start)
            CLEAN_START=true
            shift
            ;;
        --dev-mode)
            DEV_MODE=true
            shift
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

# If no version was provided, use the default
if [ -z "$VERSION" ]; then
    VERSION="$DEFAULT_VERSION"
    echo "No version specified. Using default version: $VERSION"
fi

# Determine the host system and architecture
HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)

# Function to clean up QEMU VM and Docker container
cleanup_mac() {
    echo "Cleaning up..."
    sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost "sudo docker stop hpkv-container || true; sudo docker rm hpkv-container || true; sudo docker rmi hpkv-image:${VERSION}-amd64 || true" || true
    pkill qemu-system-x86_64 || true
    rm -f cloud-init.iso
    echo "Cleanup complete."
}

# Function to clean up QEMU-related files
clean_qemu_files() {
    echo "Cleaning up QEMU-related files..."
    rm -f ubuntu-22.04-desktop-amd64.iso
    rm -f ubuntu-vm-disk.qcow2
    rm -f cloud-init.iso
    rm -f user-data
    rm -f meta-data
    echo "QEMU-related files cleaned up."
}

if [ "$HOST_OS" = "Darwin" ]; then
    echo "macOS detected. Setting up Linux VM..."

    # If clean start is requested, remove QEMU-related files
    if [ "$CLEAN_START" = true ]; then
        clean_qemu_files
    fi

    # Check if QEMU is installed
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        echo "QEMU is not installed. Installing via Homebrew..."
        if ! command -v brew &> /dev/null; then
            echo "Homebrew is not installed. Please install Homebrew first."
            exit 1
        fi
        brew install qemu
    fi

    # Check if cdrtools is installed
    if ! command -v mkisofs &> /dev/null; then
        echo "cdrtools is not installed. Installing via Homebrew..."
        brew install cdrtools
    fi

    # Check if sshpass is installed
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass is not installed. Installing via Homebrew..."
        brew install hudochenkov/sshpass/sshpass
    fi

    # Download Ubuntu Server image if not present
    UBUNTU_IMAGE="ubuntu-24.04-server-cloudimg-amd64.img"
    if [ ! -f "$UBUNTU_IMAGE" ]; then
        echo "Downloading Ubuntu 24.04 LTS Server image..."
        wget "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    fi

    # Create a larger disk image based on the downloaded image
    DISK_IMAGE="ubuntu-vm-disk.qcow2"
    if [ ! -f "$DISK_IMAGE" ]; then
        qemu-img create -f qcow2 -F qcow2 -b "$UBUNTU_IMAGE" "$DISK_IMAGE" 20G
    fi

    # Create cloud-init configuration
    cat > user-data <<EOF
#cloud-config
password: ubuntu
chpasswd: { expire: False }
ssh_pwauth: True
users:
  - default
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin
    shell: /bin/bash
    lock_passwd: false
EOF

    # Create meta-data file (empty is fine for our purposes)
    touch meta-data

    # Create cloud-init ISO
    if ! mkisofs -output cloud-init.iso -volid cidata -joliet -rock user-data meta-data; then
        echo "Failed to create cloud-init ISO. Exiting."
        exit 1
    fi

    # Check if QEMU VM is already running
    if pgrep -f "qemu-system-x86_64.*$DISK_IMAGE" > /dev/null; then
        echo "QEMU VM is already running. Attempting to use existing VM..."
        if sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost -o ConnectTimeout=5 "exit" 2>/dev/null; then
            echo "Successfully connected to existing VM."
        else
            echo "Failed to connect to existing VM. Stopping and removing it..."
            pkill qemu-system-x86_64
            sleep 5
        fi
    fi

    # Start the Ubuntu VM if not already running
    if ! pgrep -f "qemu-system-x86_64.*$DISK_IMAGE" > /dev/null; then
        echo "Starting Ubuntu VM..."
        qemu-system-x86_64 -m 4096 -smp 2 \
            -drive file="$DISK_IMAGE",format=qcow2 \
            -drive file=cloud-init.iso,format=raw \
            -net nic -net user,hostfwd=tcp::3000-:3000,hostfwd=tcp::2222-:22 \
            -nographic \
            > qemu_output.log 2>&1 &

        # Store the QEMU process ID
        QEMU_PID=$!

        # Wait for the VM to boot and become accessible
        echo "Waiting for VM to boot..."
        for i in {1..60}; do
            if sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost "exit" 2>/dev/null; then
                echo "VM is ready."
                break
            fi
            if [ $i -eq 60 ]; then
                echo "Failed to start VM. Exiting."
                kill $QEMU_PID
                exit 1
            fi
            sleep 5
        done
    fi

    trap graceful_shutdown EXIT INT TERM

    graceful_shutdown() {

        echo "Initiating graceful shutdown and cleanup..."
        
        # Stop the Docker container
        sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost "sudo docker stop hpkv-container" || true
        
        # Perform cleanup
        cleanup_mac
        
        # Exit the script
        exit 0
    }

    run_setup_and_container() {
        sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost << EOF
            # Update and upgrade the system
            echo "Updating and upgrading the system..."
            sudo apt-get update
            sudo apt-get upgrade -y
            sudo apt-get install build-essential gcc wget -y

            # Check if a reboot is required
            if [ -f /var/run/reboot-required ]; then
                echo "Reboot required. Rebooting now..."
                sudo reboot
                exit 1  # Exit with status 1 to indicate reboot
            fi

            # Check if Docker is installed
            if ! command -v docker &> /dev/null; then
                echo "Docker not found. Installing..."
                sudo apt-get update
                sudo apt-get install -y docker.io
                sudo usermod -aG docker ubuntu
            fi
            
            # Set architecture variables
            ARCH=\$(uname -m)
            case \${ARCH} in
                x86_64)
                    DOCKER_ARCH="amd64"
                    ;;
                aarch64)
                    DOCKER_ARCH="arm64"
                    ;;
                *)
                    echo "Unsupported architecture: \${ARCH}"
                    exit 2
                    ;;
            esac

            # Find the latest local image for the specified version
            LATEST_LOCAL_IMAGE=\$(sudo docker images --format "{{.Repository}}:{{.Tag}}" | grep "hpkv-image:${VERSION}-\${DOCKER_ARCH}" | sort -r | head -n 1)

            if [ -n "\$LATEST_LOCAL_IMAGE" ]; then
                echo "Found latest local image: \$LATEST_LOCAL_IMAGE"
            else
                echo "No local image found. Downloading Docker image..."
                wget "https://github.com/mehrantsi/high-performance-kv-store/releases/download/${VERSION}/hpkv-image-\${DOCKER_ARCH}.tar.gz"
                echo "Loading Docker image..."
                sudo docker load < hpkv-image-\${DOCKER_ARCH}.tar.gz
                rm hpkv-image-\${DOCKER_ARCH}.tar.gz
                LATEST_LOCAL_IMAGE="hpkv-image:${VERSION}-\${DOCKER_ARCH}"
            fi

            # Stop existing container if running
            sudo docker stop hpkv-container || true
            echo "Waiting for container to stop..."
            while sudo docker ps | grep -q hpkv-container; do
                sleep 1
            done
            sudo docker rm hpkv-container || true
            echo "Waiting for container to be removed..."
            while sudo docker ps -a | grep -q hpkv-container; do
                sleep 1
            done

            echo "Running Docker container with the latest image..."
            sudo docker run -d --rm \
              --name hpkv-container \
              --privileged \
              --device /dev/loop-control:/dev/loop-control \
              -p 3000:3000 \
              "\$LATEST_LOCAL_IMAGE" \
              /app/start.sh
            
            echo "Waiting for container to start..."
            while ! sudo docker ps | grep -q hpkv-container; do
                sleep 1
            done

            if [ ! "$DEV_MODE" ]; then
                echo "Container started. Attaching to logs..."
                (sudo docker logs -f hpkv-container & echo $! >&3) 3>docker_logs_pid
                DOCKER_LOGS_PID=$(cat docker_logs_pid)
                wait $DOCKER_LOGS_PID
            fi
EOF
    }

    # Run the setup and container function
    run_setup_and_container

    if [ $DEV_MODE ]; then
        echo "Developer mode is active. Entering SSH shell..."
        sshpass -p "ubuntu" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost
    else
        # Check the exit status of the SSH command
        SSH_EXIT_STATUS=$?

        if [ $SSH_EXIT_STATUS -eq 0 ]; then
            echo "Container has exited normally. Initiating cleanup..."
            graceful_shutdown
        elif [ $SSH_EXIT_STATUS -eq 255 ]; then
            echo "SSH connection closed unexpectedly. This might be due to Ctrl+C. Initiating cleanup..."
            graceful_shutdown
        else
            echo "An error occurred. Exit status: $SSH_EXIT_STATUS. Initiating cleanup..."
            graceful_shutdown
        fi
    fi

else
    # Original Linux script
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

    if docker image inspect "hpkv-image:${VERSION}-${DOCKER_ARCH}" &> /dev/null; then
        echo "Docker image hpkv-image:${VERSION}-${DOCKER_ARCH} already exists. Skipping download."
    else
        # Remove old image if it exists but version or arch doesn't match
        if docker image inspect "hpkv-image" &> /dev/null; then
            OLD_VERSION=$(docker image inspect -f '{{.RepoTags}}' "hpkv-image" | grep -oP '(?<=:)[^-]+(?=-)')
            OLD_ARCH=$(docker image inspect -f '{{.RepoTags}}' "hpkv-image" | grep -oP '(?<=-)[^]]+(?=])')
            if [ "$OLD_VERSION" != "${VERSION}" ] || [ "$OLD_ARCH" != "${DOCKER_ARCH}" ]; then
                echo "Removing old image with mismatched version or architecture..."
                docker rmi "hpkv-image:$OLD_VERSION-$OLD_ARCH" || true
            fi
        fi

        echo "Downloading Docker image..."
        wget "https://github.com/mehrantsi/high-performance-kv-store/releases/download/${VERSION}/hpkv-image-${DOCKER_ARCH}.tar.gz"
        echo "Loading Docker image..."
        docker load < hpkv-image-${DOCKER_ARCH}.tar.gz
        rm hpkv-image-${DOCKER_ARCH}.tar.gz
    fi

    # Stop existing container if running
    docker stop hpkv-container || true
    echo "Waiting for container to stop..."
    while docker ps | grep -q hpkv-container; do
        sleep 1
    done
    docker rm hpkv-container || true
    echo "Waiting for container to be removed..."
    while docker ps -a | grep -q hpkv-container; do
        sleep 1
    done

    echo "Running Docker container..."
    docker run --rm \
      --name hpkv-container \
      --privileged \
      --device /dev/loop-control:/dev/loop-control \
      -p 3000:3000 \
      "hpkv-image:${VERSION}-${DOCKER_ARCH}"

    echo "Container has exited and been removed."
fi