#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#define DEVICE_FILE "/dev/hpkv"
#define MAX_KEY_SIZE 256
#define MAX_VALUE_SIZE 1000

#define IOCTL_GET 0
#define IOCTL_DELETE 1
#define IOCTL_PARTIAL_UPDATE 2
#define IOCTL_PURGE 3

void insert_record(int fd, const char *key, const char *value) {
    char buffer[MAX_KEY_SIZE + MAX_VALUE_SIZE + 2];  // +2 for ':' and null terminator
    snprintf(buffer, sizeof(buffer), "%s:%s", key, value);
    ssize_t bytes_written = write(fd, buffer, strlen(buffer));
    if (bytes_written < 0) {
        perror("Failed to write record");
    } else {
        printf("Inserted record: %s\n", buffer);
    }
}

void retrieve_record(int fd, const char *key) {
    char value[MAX_VALUE_SIZE];
    strncpy(value, key, MAX_KEY_SIZE);
    if (ioctl(fd, IOCTL_GET, value) == 0) {
        printf("Retrieved record - Key: %s, Value: %s\n", key, value);
    } else {
        printf("Failed to retrieve record for key: %s\n", key);
    }
}

void delete_record(int fd, const char *key) {
    char buffer[MAX_KEY_SIZE];
    strncpy(buffer, key, MAX_KEY_SIZE);
    if (ioctl(fd, IOCTL_DELETE, buffer) == 0) {
        printf("Deleted record with key: %s\n", key);
    } else {
        printf("Failed to delete record with key: %s\n", key);
    }
}

void partial_update(int fd, const char *key, const char *partial_value) {
    char buffer[MAX_KEY_SIZE + MAX_VALUE_SIZE + 3];  // +3 for ':', '+', and null terminator
    snprintf(buffer, sizeof(buffer), "%s:+%s", key, partial_value);
    ssize_t bytes_written = write(fd, buffer, strlen(buffer));
    if (bytes_written < 0) {
        perror("Failed to partially update record");
    } else {
        printf("Partially updated record - Key: %s, Appended: %s\n", key, partial_value);
    }
}

void read_all_records(int fd) {
    char buffer[4096];
    ssize_t bytes_read;
    off_t offset = 0;
    printf("All records in the database:\n");
    while ((bytes_read = pread(fd, buffer, sizeof(buffer) - 1, offset)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
        offset += bytes_read;
    }
    if (bytes_read < 0) {
        perror("Failed to read records");
    }
    printf("\n");
}

void purge_data(int fd) {
    if (ioctl(fd, IOCTL_PURGE, 0) == 0) {
        printf("Successfully purged all data\n");
    } else {
        printf("Failed to purge data\n");
    }
}

int main() {
    int fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return 1;
    }

    printf("DBMS Kernel Module Feature Showcase\n");
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

    // 6. Read all records
    printf("6. Reading all records\n");
    read_all_records(fd);
    printf("\n");

    // 7. Purge all data
     printf("7. Purging all data\n");
     purge_data(fd);
     read_all_records(fd);
     printf("\n");

    // 8. Insert new records after purge
    printf("8. Inserting new records after purge\n");
    insert_record(fd, "new_key1", "new_value1");
    insert_record(fd, "new_key2", "new_value2");
    read_all_records(fd);
    printf("\n");

    close(fd);
    return 0;
}
