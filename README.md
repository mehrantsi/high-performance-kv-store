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

| Number of Records | Write Latency (ms) | Write Std Dev (ms) | Read Latency (ms) | Read Std Dev (ms) |
|-------------------|--------------------|--------------------|-------------------|--------------------|
| 100               | 0.005              | 3.593              | 0.001             | 0.001              |
| 1,000             | 0.007              | 0.023              | 0.002             | 0.002              |
| 10,000            | 0.002              | 0.019              | 0.001             | 0.039              |
| 100,000           | 0.002              | 0.023              | 0.001             | 1.517              |

As shown, HPKV maintains **exceptionally low read/write latencies** even as the dataset size increases. Write performance is highly competitive, thanks to the write buffer that batches write operations to reduce latency. This means that it takes more time to persist the data to disk (under 20ms for 100,000 sequential writes), but thanks to in-memory structures, whihch makes inserted/updated records immediately available, the apparent write latency is in the order of a few microseconds.

**Testing Environment**
- HOST: Parallels VM on MacBook Pro M3 Max
- VM OS: Ubuntu 22.04 LTS running kernel 6.8.0-45
- VM CPU: 4 CPU cores
- VM RAM: 4GB RAM
- Disk: 4GB Disk


## Advantages

1. **Minimal Latency**: Operating in kernel space eliminates context switching overhead.
2. **High Throughput**: Optimized data structures and kernel-level operations enable high-speed data processing.
3. **Persistence with Performance**: Combines the speed of in-memory operations with the durability of disk storage.
4. **Scalability**: Efficiently handles datasets from thousands to millions of records.
5. **Linux Integration**: Tightly integrated with the Linux kernel for optimal resource utilization.

## Scalability and Performance

HPKV is designed to **excel in environments requiring low-latency access to medium-sized datasets**. Its performance shines particularly for read-heavy workloads, making it ideal for caching layers and real-time data retrieval scenarios.

The use of kernel-space operations and optimized data structures allows HPKV to **maintain consistent, microsecond-level read latencies** even as the dataset grows to hundreds of thousands of records.

HPKV's **scalability is demonstrated by its ability to handle datasets of varying sizes with minimal performance degradation**, particularly for read operations. This makes it a versatile choice for applications with growing data needs.

## Technical Design

For a detailed technical design of the HPKV module, please refer to the [Technical Design Document](TechnicalDesign.md).

## Getting Started

### Prerequisites

- Linux kernel version 6.8.x
- GCC
- Make
- Root access (for loading the module and creating the device node)

> [!WARNING]
> 
> HPKV performs low-level disk operations and does not use traditional filesystems. it automatically checks for a valid HPKV signature on the disk and can also initialize the disk if it is empty. Make sure you're attaching a dedicated, unformatted disk to HPKV.

### Compilation and Installation

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

### Usage

After loading the module and creating the device node, you can interact with it through the `/dev/hpkv` device file. Use standard file operations to read and write data.

#### Example Usage in C

```c
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define HPKV_IOCTL_GET 0
#define HPKV_IOCTL_DELETE 1

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

    // Delete a key-value pair
    if (ioctl(fd, HPKV_IOCTL_DELETE, "mykey") == 0) {
        printf("Key 'mykey' deleted successfully\n");
    } else {
        perror("Failed to delete key");
    }

    close(fd);
    return 0;
}
```

Compile and run your program with:

```sh
gcc -o myprogram myprogram.c
./myprogram
```

> [!NOTE]
>
> Depending on the permissions you set for the device node, you may need to run the program with sudo.

#### Example Usage from Terminal

1. **Insert/Update a key-value pair:**

   ```sh
   echo -n "mykey:myvalue" | sudo dd of=/dev/hpkv
   ```

2. **Read a value by key:**

   ```sh
   sudo cat /dev/hpkv | grep "mykey:"
   ```
   > FOR TESTING PURPOSE ONLY! This command will return the entire content of the device, including all key-value pairs. If you have a large dataset, this may take a while.

3. **Delete a key-value pair:**

   > This command is executed via ioctl and must be done via a program, not a shell command.

4. **Partial update of a key-value pair:**

   ```sh
   echo -n "mykey:+partialupdate" | sudo dd of=/dev/hpkv
   ```

## Contributing

We welcome contributions!

## License

HPKV is released under the GNU General Public License v2.0 (GPLv2). See [License](LICENSE) for more details.
