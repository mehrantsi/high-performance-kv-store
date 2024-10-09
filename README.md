# High-Performance KV Store (HPKV)

HPKV is a high-performance, kernel-space key-value store designed for Linux systems. It offers exceptional read and write performance, especially for datasets ranging from 10,000 to 10,000,000 records.

## What is HPKV?

HPKV is a Linux kernel module that implements a key-value store directly in kernel space. It's designed to provide **high-performance data storage and retrieval** with **minimal latency**, making it ideal for applications that require fast access to structured data.

## Use Cases

- Real-time analytics engines
- Caching layers for high-traffic web applications
- IoT data collection and processing systems
- High-frequency trading systems
- Any application requiring fast, low-latency data access

## How It Works

HPKV operates entirely in kernel space, eliminating the overhead of context switches between user and kernel space. It uses a combination of hash tables for fast lookups and red-black trees for efficient range queries. Data is persisted to a block device, ensuring durability while maintaining high performance.

Key features of its operation include:

- Direct kernel space operations for minimal latency
- Efficient memory management using kernel slabs
- Optimized disk I/O with block device operations
- Concurrent access support with fine-grained locking
- Write buffering to batch write operations and reduce latency
- Automatic disk compaction to optimize disk usage
- Support for partial updates to existing records
- Robust error handling and recovery mechanisms

## Features

- **Fast read and write operations**
- Range queries
- Partial updates
- Automatic disk compaction
- Data persistence
- Configurable caching
- Robust error handling and recovery

## Performance Comparison

HPKV offers **superior performance** compared to many traditional key-value stores, especially for read operations and smaller to medium-sized datasets.

### Performance Benchmarks

Here's a table showing the performance of HPKV for different dataset sizes:

| Number of Records | Operation | Median Latency (ms) | Mean Latency (ms) | Std Dev (ms) | Min (ms) | Max (ms) | P95 (ms) | P99 (ms) |
|-------------------|-----------|---------------------|-------------------|--------------|----------|----------|----------|----------|
| 100               | Write     | 0.005               | 0.007             | 0.023        | 0.001    | 0.200    | 0.015    | 0.050    |
|                   | Read      | 0.001               | 0.002             | 0.002        | 0.001    | 0.010    | 0.005    | 0.008    |
|                   | Delete    | 0.002               | 0.003             | 0.002        | 0.001    | 0.015    | 0.007    | 0.010    |
| 1,000             | Write     | 0.007               | 0.008             | 0.025        | 0.002    | 0.250    | 0.020    | 0.060    |
|                   | Read      | 0.002               | 0.003             | 0.003        | 0.001    | 0.020    | 0.008    | 0.012    |
|                   | Delete    | 0.003               | 0.004             | 0.003        | 0.001    | 0.025    | 0.010    | 0.015    |
| 10,000            | Write     | 0.002               | 0.003             | 0.019        | 0.001    | 0.300    | 0.025    | 0.070    |
|                   | Read      | 0.001               | 0.002             | 0.039        | 0.001    | 0.030    | 0.010    | 0.015    |
|                   | Delete    | 0.002               | 0.003             | 0.002        | 0.001    | 0.035    | 0.012    | 0.018    |
| 100,000           | Write     | 0.002               | 0.003             | 0.023        | 0.001    | 0.350    | 0.030    | 0.080    |
|                   | Read      | 0.001               | 0.002             | 1.517        | 0.001    | 0.040    | 0.012    | 0.020    |
|                   | Delete    | 0.002               | 0.003             | 0.003        | 0.001    | 0.045    | 0.015    | 0.025    |

As shown, HPKV maintains **exceptionally low read/write latencies** even as the dataset size increases. Write performance is highly competitive, thanks to the write buffer that batches write operations to reduce latency. This means that it takes more time to persist the data to disk (under 20ms for 100,000 sequential writes), but thanks to in-memory structures, which makes inserted/updated records immediately available, the apparent write latency is in the order of a few microseconds.

**Testing Environment**
- Host: MacBook Pro M3 Max
- Virtualization: QEMU virtual machine
- VM Specifications:
  - Memory: 4096 MB (4 GB)
  - CPU: 2 cores
  - Disk: 20 GB
- Guest OS: Ubuntu 24.04 LTS Server
- Docker Container:
  - Running inside the QEMU VM
  - Privileged mode with access to /dev/loop-control
  - Exposed port: 3000
- Network: Port forwarding from host 3000 to guest 3000

Note: The performance metrics were collected from within the Docker container, which was running inside the QEMU virtual machine. This setup may introduce additional overhead compared to bare-metal or native virtualization solutions.

## Scalability and Performance

HPKV is designed to **excel in environments requiring low-latency access to medium-sized datasets**. Its performance shines particularly for read-heavy workloads, making it ideal for caching layers and real-time data retrieval scenarios.

The use of kernel-space operations and optimized data structures allows HPKV to **maintain consistent, microsecond-level read latencies** even as the dataset grows to hundreds of thousands of records.

HPKV's **scalability is demonstrated by its ability to handle datasets of varying sizes with minimal performance degradation**, particularly for read operations. This makes it a versatile choice for applications with growing data needs.

## Technical Design

For a detailed technical design of the HPKV module, please refer to the [Technical Design Document](TechnicalDesign.md).

## Getting Started

### Running with Docker

HPKV can be run using Docker containers, which simplifies setup and ensures consistency across different environments. There are two main scripts to manage the HPKV environment: `docker-run.sh` and `dev-update.sh`.

#### docker-run.sh

This script sets up and runs the HPKV Docker container. It supports both Linux and macOS environments.

##### Basic Usage:

```sh
./docker-run.sh [VERSION]
```

If no version is specified, it defaults to the latest version available on GitHub.

##### Options:

- `--clean-start`: Performs a clean start by removing QEMU-related files (macOS only).
- `--dev-mode`: Enters developer mode, providing an SSH shell for direct interaction with the VM (macOS only).

##### Scenarios:

1. **Standard Run (Linux):**
   ```sh
   ./docker-run.sh
   ```
   This will download the Docker image (if not present), start the HPKV container, and attach to its logs.

2. **Specific Version (Linux/macOS):**
   ```sh
   ./docker-run.sh v1.3
   ```
   Runs the specified version of the HPKV image.

3. **Clean Start on macOS:**
   ```sh
   ./docker-run.sh --clean-start
   ```
   Removes existing QEMU files before starting the VM and container.

4. **Developer Mode on macOS:**
   ```sh
   ./docker-run.sh --dev-mode
   ```
   Starts the VM and container, then provides an SSH shell for development.

##### macOS Specifics:

On macOS, the script sets up a QEMU VM running Ubuntu, which then hosts the Docker container. This approach allows kernel module development on macOS.

#### dev-update.sh

This script facilitates rapid development by updating the HPKV module and API server without rebuilding the entire Docker image.

##### Usage:

```sh
./dev-update.sh [VERSION]
```

If no version is specified, it defaults to the latest version available on GitHub.

##### Functionality:

1. Copies updated `hpkv_module.c`, `Makefile`, `start.sh` and `server.js` files to the container.
2. Rebuilds the kernel module inside the container.
3. Updates the API server code.
4. Commits changes to a new Docker image.
5. Restarts the container with the updated image.

##### Scenarios:

1. **Quick Update During Development:**
   After making changes to the kernel module or API server:
   ```sh
   ./dev-update.sh
   ```
   This updates the running container with your latest changes.

2. **Update Specific Version:**
   ```sh
   ./dev-update.sh v1.3-docker
   ```
   Updates the specified version of the HPKV image.

#### Kernel Development on macOS

For kernel development on macOS, use the following workflow:

1. Start the environment in dev-mode:
   ```sh
   ./docker-run.sh --dev-mode
   ```

2. Make changes to `kernel/hpkv_module.c` or `api/server.js` on your host machine.

3. Run the dev-update script to apply changes:
   ```sh
   ./dev-update.sh
   ```

4. To view the container logs:
   ```sh
   docker logs -f hpkv-container
   ```

5. To view the kernel module logs:
   ```sh
   sudo dmesg --follow
   ```

##### Notes

- On macOS, the scripts will automatically install necessary dependencies like QEMU and sshpass if they're not present.
- In developer mode, exiting the SSH shell shuts down the VM and performs an automatic cleanup.

By using these scripts, you can perform rapid development iterations.

### Local Compilation and Installation

#### Prerequisites

- Linux kernel version 6.8.0-xx
- GCC
- Make
- Root access (for loading the module and creating the device node)

> [!WARNING]
> 
> HPKV performs low-level disk operations and does not use traditional filesystems. it automatically checks for a valid HPKV signature on the disk and can also initialize the disk if it is empty. Make sure you're attaching a dedicated, unformatted disk to HPKV.

#### Compilation and Installation Steps

1. Clone the repository:
   ```sh
   git clone https://github.com/mehrantsi/high-performance-kv-store.git
   cd high-performance-kv-store/kernel
   ```

2. Install Essential Packages:
   First, you need to install the necessary development tools and kernel headers. On Ubuntu or Debian-based systems, you can do this with:
   ```sh
   sudo apt-get update
   sudo apt-get install build-essential linux-headers-$(uname -r)
   ```
   On Red Hat-based systems (like CentOS or Fedora), use:
   ```sh
   sudo yum groupinstall "Development Tools"
   sudo yum install kernel-devel kernel-headers
   ```
   
3. Verify Kernel Headers:
   Ensure that the kernel headers are installed for your current kernel version:
   ```sh
   ls /lib/modules/$(uname -r)/build
   ```
   
4. Compile the module:
   ```sh
   make
   ```
   This will compile the `hpkv_module.c` file and create the kernel module `hpkv.ko`.

5. Load the module:
   ```sh
   sudo insmod hpkv.ko
   ```
   You can specify the mount path for the block device by adding a parameter:
   ```sh
   sudo insmod hpkv.ko mount_path="/dev/sdb"
   ```
   You can also specify initialize_if_empty flag to not initialize the disk if it is empty (default is 1):
   ```sh
   sudo insmod hpkv.ko mount_path="/dev/sdb" initialize_if_empty=0
   ```
     
6. Verify that the module is loaded:
   ```sh
   lsmod | grep hpkv
   ```

7. Create a device node:
   First, check the major number assigned to the module:
   ```sh
   dmesg | grep "hpkv: registered with major number"
   ```
   You should see a line like "hpkv: registered with major number 234" (the number may be different).

   Now, create the device node:
   ```sh
   sudo mknod /dev/hpkv c <major_number> 0
   ```
   Replace <major_number> with the number you found in the previous step.

8. Set appropriate permissions for the device node:
   ```sh
   sudo chmod 666 /dev/hpkv
   ```
   This allows read and write access for all users. Adjust the permissions as needed for your security requirements.

9. To unload the module:
   ```sh
   sudo rmmod hpkv
   ```
   Note: Remember to remove the device node when you're done:
   ```sh
   sudo rm /dev/hpkv
   ```

## License

HPKV is released under the GNU AFFERO GENERAL PUBLIC LICENSE (AGPLv3). See [License](LICENSE) for more details.