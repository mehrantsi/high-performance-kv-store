#!/bin/bash

set -e
set -x

# Create a file to use as a block device if it doesn't exist
if [ ! -f /app/hpkv_disk.img ]; then
    dd if=/dev/zero of=/app/hpkv_disk.img bs=1M count=1024
fi

# Detach any existing loop devices associated with our disk image
EXISTING_LOOP=$(losetup -j /app/hpkv_disk.img | cut -d ':' -f 1)
if [ ! -z "$EXISTING_LOOP" ]; then
    losetup -d $EXISTING_LOOP
fi

# List available loop devices
ls -l /dev/loop*

# Find the first available loop device
LOOP_DEVICE=$(losetup -f)
echo "Using loop device: $LOOP_DEVICE"

# Set up the loop device
losetup $LOOP_DEVICE /app/hpkv_disk.img

# Load the kernel module
cd /app/kernel
insmod hpkv_module.ko mount_path=$LOOP_DEVICE

# Start the Node.js server
cd /app/api
node server.js &

# Keep the container running
tail -f /dev/null