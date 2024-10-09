#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>

#define DEVICE_FILE "/dev/hpkv"
#define MAX_KEY_SIZE 512
#define MAX_VALUE_SIZE 102400  // 100 KB

#define HPKV_IOCTL_GET 0
#define HPKV_IOCTL_DELETE 1
#define HPKV_IOCTL_PARTIAL_UPDATE 5
#define HPKV_IOCTL_INSERT 4

void insert_record(int fd, const char *key, const char *value) {
    char buffer[MAX_KEY_SIZE + sizeof(size_t) + MAX_VALUE_SIZE];
    uint16_t key_len = strlen(key);
    size_t value_len = strlen(value);

    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), &value_len, sizeof(size_t));
    memcpy(buffer + sizeof(uint16_t) + sizeof(size_t), key, key_len);
    memcpy(buffer + sizeof(uint16_t) + sizeof(size_t) + key_len, value, value_len);

    if (ioctl(fd, HPKV_IOCTL_INSERT, buffer) == 0) {
        printf("Inserted record: Key=%.20s%s, Value=%.20s%s\n", 
               key, (key_len > 20 ? "..." : ""),
               value, (value_len > 20 ? "..." : ""));
    } else {
        perror("Failed to insert record");
    }
}

void retrieve_record(int fd, const char *key) {
    char buffer[MAX_KEY_SIZE + sizeof(size_t) + MAX_VALUE_SIZE];
    uint16_t key_len = strlen(key);
    size_t value_len;
    
    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), key, key_len);
    
    if (ioctl(fd, HPKV_IOCTL_GET, buffer) == 0) {
        memcpy(&value_len, buffer + sizeof(uint16_t), sizeof(size_t));
        buffer[sizeof(uint16_t) + sizeof(size_t) + value_len] = '\0';
        char *value = buffer + sizeof(uint16_t) + sizeof(size_t);
        printf("Retrieved record - Key: %.20s%s, Value: %.20s%s, Length: %zu\n", 
               key, (key_len > 20 ? "..." : ""),
               value, (value_len > 20 ? "..." : ""),
               value_len);
    } else {
        if (errno == ENOENT) {
            printf("Record not found for key: %.20s%s\n", 
                   key, (key_len > 20 ? "..." : ""));
        } else {
            perror("Failed to retrieve record");
        }
    }
}

void delete_record(int fd, const char *key) {
    char buffer[MAX_KEY_SIZE];
    uint16_t key_len = strlen(key);
    
    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), key, key_len);
    
    if (ioctl(fd, HPKV_IOCTL_DELETE, buffer) == 0) {
        printf("Deleted record with key: %.20s%s\n", 
               key, (key_len > 20 ? "..." : ""));
    } else {
        printf("Failed to delete record with key: %.20s%s\n", 
               key, (key_len > 20 ? "..." : ""));
    }
}

void partial_update(int fd, const char *key, const char *partial_value) {
    char buffer[MAX_KEY_SIZE + sizeof(size_t) + MAX_VALUE_SIZE];
    uint16_t key_len = strlen(key);
    size_t value_len = strlen(partial_value);

    memcpy(buffer, &key_len, sizeof(uint16_t));
    memcpy(buffer + sizeof(uint16_t), &value_len, sizeof(size_t));
    memcpy(buffer + sizeof(uint16_t) + sizeof(size_t), key, key_len);
    memcpy(buffer + sizeof(uint16_t) + sizeof(size_t) + key_len, partial_value, value_len);

    if (ioctl(fd, HPKV_IOCTL_PARTIAL_UPDATE, buffer) == 0) {
        printf("Partially updated record - Key: %.20s%s, Appended: %.20s%s\n", 
               key, (key_len > 20 ? "..." : ""),
               partial_value, (value_len > 20 ? "..." : ""));
    } else {
        perror("Failed to partially update record");
    }
}

int main() {
    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }

    printf("HPKV Kernel Module Feature Showcase\n");
    printf("===================================\n\n");

    // 1. Insert records
    printf("1. Inserting records\n");
    insert_record(fd, "key1", "value1");
    insert_record(fd, "key2", "value2");
    insert_record(fd, "key3", "value3");
    printf("\n");

    // 2. Retrieve records
    printf("2. Retrieving records\n");
    retrieve_record(fd, "key1");
    retrieve_record(fd, "key2");
    retrieve_record(fd, "nonexistent_key");
    printf("\n");

    // 3. Update a record
    printf("3. Updating a record\n");
    insert_record(fd, "key2", "updated_value2");
    retrieve_record(fd, "key2");
    printf("\n");

    // 4. Partial update
    printf("4. Performing partial update\n");
    partial_update(fd, "key1", "_appended");
    retrieve_record(fd, "key1");
    printf("\n");

    // 5. Delete a record
    printf("5. Deleting a record\n");
    delete_record(fd, "key3");
    retrieve_record(fd, "key3");
    printf("\n");

    // 6. Read individual records
    printf("6. Reading individual records\n");
    retrieve_record(fd, "key1");
    retrieve_record(fd, "key2");
    printf("\n");

    // 7. Test large key and value
    printf("7. Testing large key and value\n");
    char *large_key = malloc(MAX_KEY_SIZE);
    char *large_value = malloc(MAX_VALUE_SIZE);
    memset(large_key, 'K', MAX_KEY_SIZE - 1);
    large_key[MAX_KEY_SIZE - 1] = '\0';
    memset(large_value, 'V', MAX_VALUE_SIZE - 1);
    large_value[MAX_VALUE_SIZE - 1] = '\0';

    insert_record(fd, large_key, large_value);
    retrieve_record(fd, large_key);
    delete_record(fd, large_key);

    free(large_key);
    free(large_value);
    printf("\n");

    close(fd);
    return 0;
}