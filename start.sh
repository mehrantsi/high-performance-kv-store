#!/bin/bash

set -e
set -x

# Determine the system architecture
ARCH=$(uname -m)
case ${ARCH} in
    x86_64)
        MODULE_ARCH="x86_64"
        ;;
    aarch64)
        MODULE_ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

# Create a file to use as a block device if it doesn't exist
if [ ! -f /app/persistent_storage/hpkv_disk.img ]; then
    dd if=/dev/zero of=/app/persistent_storage/hpkv_disk.img bs=1M count=1024
fi

# Detach any existing loop devices associated with our disk image
EXISTING_LOOP=$(losetup -j /app/persistent_storage/hpkv_disk.img | cut -d ':' -f 1)
if [ ! -z "$EXISTING_LOOP" ]; then
    losetup -d $EXISTING_LOOP
fi

# List available loop devices
ls -l /dev/loop*

# Find the first available loop device
LOOP_DEVICE=$(losetup -f)
echo "Using loop device: $LOOP_DEVICE"

# Set up the loop device
losetup $LOOP_DEVICE /app/persistent_storage/hpkv_disk.img

# Load the kernel module
cd /app/kernel
insmod hpkv_module_${MODULE_ARCH}.ko mount_path=$LOOP_DEVICE

# Create the device node
mknod /dev/hpkv c $(cat /proc/devices | grep hpkv | cut -d' ' -f1) 0

# Set permissions for the device node
chmod 666 /dev/hpkv

# Start the Node.js server
cd /app/api
node server.js &

# Function to handle cleanup
cleanup() {
    echo "Cleaning up..."
    # Stop the Node.js server
    pkill -f "node server.js"
    # Unload the kernel module
    rmmod hpkv_module
    # Remove the device node
    rm -f /dev/hpkv
    # Remove any leftover loop devices
    losetup -D
}

# Set up trap to call cleanup function on exit
trap cleanup EXIT

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?