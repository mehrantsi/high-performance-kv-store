#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <stdint.h>

#define DEVICE_FILE "/dev/hpkv"
#define MAX_KEY_SIZE 512
#define MAX_VALUE_SIZE 102400  // 100 KB

#define HPKV_IOCTL_GET 0
#define HPKV_IOCTL_DELETE 1
#define HPKV_IOCTL_PARTIAL_UPDATE 5
#define HPKV_IOCTL_INSERT 4

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

double calculate_std_dev(Latencies* latencies, double mean) {
    double sum = 0.0;
    for (int i = 0; i < latencies->size; i++) {
        double diff = latencies->data[i] - mean;
        sum += diff * diff;
    }
    return sqrt(sum / latencies->size);
}

double calculate_percentile(Latencies* latencies, double percentile) {
    int index = (int)(percentile * latencies->size);
    return latencies->data[index];
}

void insert_record(int fd, const char* key, const char* value, Latencies* write_latencies) {
    char buffer[MAX_KEY_SIZE + sizeof(size_t) + MAX_VALUE_SIZE];
    uint16_t key_len = strlen(key);
    size_t value_len = strlen(value);
    
    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), &value_len, sizeof(size_t));
    memcpy(buffer + sizeof(uint16_t) + sizeof(size_t), key, key_len);
    memcpy(buffer + sizeof(uint16_t) + sizeof(size_t) + key_len, value, value_len);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    if (ioctl(fd, HPKV_IOCTL_INSERT, buffer) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / NANO_TO_MILLI;
        write_latencies->data[write_latencies->size++] = latency;
    } else {
        perror("Failed to insert record");
    }
}

void retrieve_record(int fd, const char* key, Latencies* read_latencies) {
    char buffer[MAX_KEY_SIZE + sizeof(size_t) + MAX_VALUE_SIZE];
    uint16_t key_len = strlen(key);
    size_t value_len;
    
    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), key, key_len);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    if (ioctl(fd, HPKV_IOCTL_GET, buffer) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &end);
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

void delete_record(int fd, const char* key, Latencies* delete_latencies) {
    char buffer[MAX_KEY_SIZE];
    uint16_t key_len = strlen(key);
    
    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), key, key_len);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    if (ioctl(fd, HPKV_IOCTL_DELETE, buffer) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &end);
        double latency = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / NANO_TO_MILLI;
        delete_latencies->data[delete_latencies->size++] = latency;
    } else {
        perror("Failed to delete record");
    }
}

void run_test(int fd, int num_records) {
    Latencies write_latencies = {malloc(num_records * sizeof(double)), 0};
    Latencies read_latencies = {malloc(num_records * sizeof(double)), 0};
    Latencies delete_latencies = {malloc(num_records * sizeof(double)), 0};
    
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
    
    // Delete records
    for (int i = 0; i < num_records; i++) {
        snprintf(key, sizeof(key), "key_%d_%d", num_records, i);
        delete_record(fd, key, &delete_latencies);
    }
    
    // Calculate statistics
    qsort(write_latencies.data, write_latencies.size, sizeof(double), compare_doubles);
    qsort(read_latencies.data, read_latencies.size, sizeof(double), compare_doubles);
    qsort(delete_latencies.data, delete_latencies.size, sizeof(double), compare_doubles);

    double write_median = calculate_median(&write_latencies);
    double read_median = calculate_median(&read_latencies);
    double delete_median = calculate_median(&delete_latencies);
    
    double write_mean = 0.0, read_mean = 0.0, delete_mean = 0.0;
    for (int i = 0; i < num_records; i++) {
        write_mean += write_latencies.data[i];
        read_mean += read_latencies.data[i];
        delete_mean += delete_latencies.data[i];
    }
    write_mean /= num_records;
    read_mean /= num_records;
    delete_mean /= num_records;
    
    double write_std_dev = calculate_std_dev(&write_latencies, write_mean);
    double read_std_dev = calculate_std_dev(&read_latencies, read_mean);
    double delete_std_dev = calculate_std_dev(&delete_latencies, delete_mean);
    
    printf("Results for %d records:\n", num_records);
    printf("Write  - Median: %.3f ms, Mean: %.3f ms, Std Dev: %.3f ms, Min: %.3f ms, Max: %.3f ms, P95: %.3f ms, P99: %.3f ms\n",
           write_median, write_mean, write_std_dev, write_latencies.data[0], write_latencies.data[num_records-1],
           calculate_percentile(&write_latencies, 0.95), calculate_percentile(&write_latencies, 0.99));
    printf("Read   - Median: %.3f ms, Mean: %.3f ms, Std Dev: %.3f ms, Min: %.3f ms, Max: %.3f ms, P95: %.3f ms, P99: %.3f ms\n",
           read_median, read_mean, read_std_dev, read_latencies.data[0], read_latencies.data[num_records-1],
           calculate_percentile(&read_latencies, 0.95), calculate_percentile(&read_latencies, 0.99));
    printf("Delete - Median: %.3f ms, Mean: %.3f ms, Std Dev: %.3f ms, Min: %.3f ms, Max: %.3f ms, P95: %.3f ms, P99: %.3f ms\n",
           delete_median, delete_mean, delete_std_dev, delete_latencies.data[0], delete_latencies.data[num_records-1],
           calculate_percentile(&delete_latencies, 0.95), calculate_percentile(&delete_latencies, 0.99));
    
    free(write_latencies.data);
    free(read_latencies.data);
    free(delete_latencies.data);
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
    
    close(fd);
    return 0;
}