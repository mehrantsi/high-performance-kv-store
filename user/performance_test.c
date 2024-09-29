#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>
#include <math.h>
#include <errno.h>

#define DEVICE_FILE "/dev/hpkv"
#define MAX_KEY_SIZE 256
#define MAX_VALUE_SIZE 1000

#define IOCTL_GET 0
#define IOCTL_PURGE 3

#define NANO_TO_MILLI 1000000.0

typedef struct {
    double* data;
    int size;
} Latencies;

// Function to compare doubles for qsort
int compare_doubles(const void* a, const void* b) {
    double arg1 = *(const double*)a;
    double arg2 = *(const double*)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

double calculate_median(Latencies* latencies) {
    qsort(latencies->data, latencies->size, sizeof(double), compare_doubles);
    if (latencies->size % 2 == 0) {
        return (latencies->data[latencies->size/2 - 1] + latencies->data[latencies->size/2]) / 2.0;
    } else {
        return latencies->data[latencies->size/2];
    }
}

double my_sqrt(double x) {
    if (x <= 0) return 0;
    double guess = x / 2;
    double epsilon = 0.000001;
    while ((guess * guess - x) > epsilon || (x - guess * guess) > epsilon) {
        guess = (guess + x / guess) / 2;
    }
    return guess;
}

double calculate_std_dev(Latencies* latencies, double mean) {
    double sum = 0.0;
    for (int i = 0; i < latencies->size; i++) {
        double diff = latencies->data[i] - mean;
        sum += diff * diff;
    }
    return my_sqrt(sum / latencies->size);
}

void insert_record(int fd, const char* key, const char* value, Latencies* write_latencies) {
    char buffer[MAX_KEY_SIZE + MAX_VALUE_SIZE + 2];
    snprintf(buffer, sizeof(buffer), "%s:%s", key, value);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    ssize_t bytes_written = write(fd, buffer, strlen(buffer));
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    if (bytes_written < 0) {
        perror("Failed to write record");
    } else {
        double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / NANO_TO_MILLI;
        write_latencies->data[write_latencies->size++] = latency;
    }
}

void retrieve_record(int fd, const char* key, Latencies* read_latencies) {
    char buffer[MAX_KEY_SIZE + sizeof(size_t) + MAX_VALUE_SIZE];
    size_t value_len;
    
    // Copy the key to the buffer
    strncpy(buffer, key, MAX_KEY_SIZE);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    if (ioctl(fd, IOCTL_GET, buffer) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        // Extract the value length
        memcpy(&value_len, buffer + MAX_KEY_SIZE, sizeof(size_t));
        
        double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / NANO_TO_MILLI;
        read_latencies->data[read_latencies->size++] = latency;
    } else {
        if (errno == ENOENT) {
            printf("Record not found for key: %s\n", key);
        } else {
            perror("Failed to retrieve record");
        }
    }
}

void purge_data(int fd) {
    if (ioctl(fd, IOCTL_PURGE, 0) == 0) {
        printf("Successfully purged all data\n");
    } else {
        printf("Failed to purge data\n");
    }
}

void run_test(int fd, int num_records) {
    Latencies write_latencies = {malloc(num_records * sizeof(double)), 0};
    Latencies read_latencies = {malloc(num_records * sizeof(double)), 0};
    
    char key[MAX_KEY_SIZE];
    char value[MAX_VALUE_SIZE];
    
    printf("Running test with %d records...\n", num_records);
    
    // Insert records
    for (int i = 0; i < num_records; i++) {
        snprintf(key, sizeof(key), "key_%d_%d", num_records, i);
        snprintf(value, sizeof(value), "value_%d_%d", num_records, i);
        insert_record(fd, key, value, &write_latencies);
    }
    
    // Read individual records
    for (int i = 0; i < num_records; i++) {
        snprintf(key, sizeof(key), "key_%d_%d", num_records, i);
        retrieve_record(fd, key, &read_latencies);
    }
    
    // Calculate statistics
    double write_median = calculate_median(&write_latencies);
    double read_median = calculate_median(&read_latencies);
    
    double write_mean = 0.0, read_mean = 0.0;
    for (int i = 0; i < num_records; i++) {
        write_mean += write_latencies.data[i];
        read_mean += read_latencies.data[i];
    }
    write_mean /= num_records;
    read_mean /= num_records;
    
    double write_std_dev = calculate_std_dev(&write_latencies, write_mean);
    double read_std_dev = calculate_std_dev(&read_latencies, read_std_dev);
    
    printf("Results for %d records:\n", num_records);
    printf("Write         - Median Latency: %.3f ms, Std Dev: %.3f ms\n", write_median, write_std_dev);
    printf("Read          - Median Latency: %.3f ms, Std Dev: %.3f ms\n", read_median, read_std_dev);
    
    free(write_latencies.data);
    free(read_latencies.data);
}

int main() {
    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }
    
    int sample_sizes[] = {100, 1000, 10000, 100000};
    int num_samples = sizeof(sample_sizes) / sizeof(sample_sizes[0]);
    
    for (int i = 0; i < num_samples; i++) {
        run_test(fd, sample_sizes[i]);
        
        // Add a small delay between tests
        usleep(100000);  // 100ms delay
    }
    
    purge_data(fd);
    
    close(fd);
    return 0;
}