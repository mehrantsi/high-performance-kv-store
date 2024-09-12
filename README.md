# Kernel Space, High-Performance KV Store (HPKV)

HPKV is a high-performance, kernel-space key-value store designed for Linux systems. It offers exceptional read and write performance, especially for datasets ranging from 10,000 to 1,000,000 records.

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

| Number of Records | Write Latency (ms) | Write Std Dev (ms) | Read Latency (ms) | Read Std Dev (ms) |
|-------------------|--------------------|--------------------|-------------------|--------------------|
| 100               | 0.086              | 0.226              | 0.001             | 0.000              |
| 1,000             | 0.157              | 0.029              | 0.000             | 0.000              |
| 10,000            | 1.517              | 0.895              | 0.001             | 0.001              |
| 100,000           | 19.794             | 8.154              | 0.001             | 0.000              |

As shown, HPKV maintains **exceptionally low read latencies** even as the dataset size increases. Write performance scales linearly with dataset size, remaining highly competitive.

## Advantages

1. **Minimal Latency**: Operating in kernel space eliminates context switching overhead.
2. **High Throughput**: Optimized data structures and kernel-level operations enable high-speed data processing.
3. **Persistence with Performance**: Combines the speed of in-memory operations with the durability of disk storage.
4. **Scalability**: Efficiently handles datasets from thousands to millions of records.
5. **Linux Integration**: Tightly integrated with the Linux kernel for optimal resource utilization.

## Scalability and Performance

HPKV is designed to **excel in environments requiring low-latency access to medium-sized datasets**. Its performance shines particularly for read-heavy workloads, making it ideal for caching layers and real-time data retrieval scenarios.

The use of kernel-space operations and optimized data structures allows HPKV to **maintain consistent, microsecond-level read latencies** even as the dataset grows to hundreds of thousands of records.

While write performance does increase with dataset size, it remains highly competitive, with median latencies staying under 20ms even for 100,000 records.

HPKV's **scalability is demonstrated by its ability to handle datasets of varying sizes with minimal performance degradation**, particularly for read operations. This makes it a versatile choice for applications with growing data needs.

## Getting Started

### Prerequisites

- Linux kernel headers (matching your current kernel version)
- GCC
- Make
- Root access (for loading the module and creating the device node)

> [!WARNING]
> 
> HPKV performs low-level disk operations and does not use traditional filesystems. Make sure you're attaching a dedicated, unformatted disk to HPKV.

### Compilation and Installation

1. Clone the repository:
   ```
   git clone https://github.com/mehrantsi/kernel-high-performance-kv-store.git
   cd kernel-high-performance-kv-store/kernel
   ```

2. Install Essential Packages:
   First, you need to install the necessary development tools and kernel headers. On Ubuntu or Debian-based systems, you can do this with:
   ```
   sudo apt-get update
   sudo apt-get install build-essential linux-headers-$(uname -r)
   ```
   On Red Hat-based systems (like CentOS or Fedora), use:
   ```
   sudo yum groupinstall "Development Tools"
   sudo yum install kernel-devel kernel-headers
   ```
   
3. Verify Kernel Headers:
   Ensure that the kernel headers are installed for your current kernel version:
   ```
   ls /lib/modules/$(uname -r)/build
   ```
   
4. Compile the module:
   ```
   make
   ```
   This will compile the `hpkv_module.c` file and create the kernel module `hpkv.ko`.

5. Load the module:
   ```
   sudo insmod hpkv.ko
   ```
   You can specify the mount path for the block device by adding a parameter:
   ```
   sudo insmod hpkv.ko mount_path="/dev/sdb"
   ```
     
6. Verify that the module is loaded:
   ```
   lsmod | grep hpkv
   ```

7. Create a device node:
   First, check the major number assigned to the module:
   ```
   dmesg | grep "hpkv: registered with major number"
   ```
   You should see a line like "hpkv: registered with major number 234" (the number may be different).

   Now, create the device node:
   ```
   sudo mknod /dev/hpkv c <major_number> 0
   ```
   Replace <major_number> with the number you found in the previous step.

8. Set appropriate permissions for the device node:
   ```
   sudo chmod 666 /dev/hpkv
   ```
   This allows read and write access for all users. Adjust the permissions as needed for your security requirements.

9. To unload the module:
   ```
   sudo rmmod hpkv
   ```
   Note: Remember to remove the device node when you're done:
   ```
   sudo rm /dev/hpkv
   ```

### Usage

After loading the module and creating the device node, you can interact with it through the `/dev/hpkv` device file. Use standard file operations to read and write data.

Example usage in C:

```c
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define HPKV_IOCTL_GET 0

int main() {
    int fd = open("/dev/hpkv", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }

    // Write a key-value pair
    char *data = "mykey:myvalue";
    write(fd, data, strlen(data));

    // Read a value by key
    char buffer[1024];
    strcpy(buffer, "mykey");
    if (ioctl(fd, HPKV_IOCTL_GET, buffer) == 0) {
        printf("Value: %s\n", buffer);
    }

    close(fd);
    return 0;
}
```

Compile and run your program with:
```
gcc -o myprogram myprogram.c
./myprogram
```

Note: Depending on the permissions you set for the device node, you may need to run the program with sudo.

## Contributing

We welcome contributions!

## License

HPKV is released under the GNU General Public License v2.0 (GPLv2). See [License](LICENSE) for more details.
