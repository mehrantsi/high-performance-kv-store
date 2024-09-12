#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rbtree.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

#define DEVICE_NAME "hpkv"
#define MAX_KEY_SIZE 256
#define MAX_VALUE_SIZE 1000
#define HPKV_HASH_BITS (20) // 2^20 = 1,048,576 buckets
#define MAX_DISK_USAGE (1UL << 30) // 1 GB max disk usage
#define BLOCK_SIZE 4096
#define PROC_ENTRY "hpkv_stats"
#define CACHE_SIZE 1000
#define COMPACT_INTERVAL (60 * HZ) // Run compaction every 60 seconds

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mehran Toosi");
MODULE_DESCRIPTION("High performance KV store kernel module, with advanced features");

static int major_num;
static struct kmem_cache *record_cache;
static DEFINE_RWLOCK(rw_lock);
static DEFINE_MUTEX(write_mutex);

struct record {
    char key[MAX_KEY_SIZE];
    char *value;
    size_t value_len;
    struct hlist_node hash_node;
    struct rb_node tree_node;
    struct rcu_head rcu;
    sector_t sector;
};

struct cached_record {
    char key[MAX_KEY_SIZE];
    char *value;
    size_t value_len;
    sector_t sector;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(kv_store, HPKV_HASH_BITS);
static struct rb_root records_tree = RB_ROOT;
static atomic_long_t total_disk_usage = ATOMIC_LONG_INIT(0);
static atomic_t record_count = ATOMIC_INIT(0);

static DEFINE_HASHTABLE(cache, 10);  // 1024 buckets
static int cache_count = 0;
static DEFINE_SPINLOCK(cache_lock);

static struct block_device *bdev;
static char *mount_path = "/dev/sdb";  // Adjust this to your persistent storage device
module_param(mount_path, charp, 0644);
MODULE_PARM_DESC(mount_path, "Path to the block device for persistent storage");

static struct workqueue_struct *compact_wq;
static struct delayed_work compact_work;

static u32 djb2_hash(const char *str, size_t len)
{
    u32 hash = 5381;
    size_t i;

    for (i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + str[i];

    return hash;
}

static struct record *search_record_in_memory(const char *key)
{
    struct rb_node *node = records_tree.rb_node;

    while (node) {
        struct record *data = container_of(node, struct record, tree_node);
        int result = strcmp(key, data->key);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return data;
    }
    return NULL;
}

static void insert_rb_tree(struct record *record)
{
    struct rb_node **new = &(records_tree.rb_node), *parent = NULL;

    while (*new) {
        struct record *this = container_of(*new, struct record, tree_node);
        int result = strcmp(record->key, this->key);

        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
            return;
    }

    rb_link_node(&record->tree_node, parent, new);
    rb_insert_color(&record->tree_node, &records_tree);
}

static struct cached_record *cache_get(const char *key)
{
    struct cached_record *cached;
    u32 hash = djb2_hash(key, strlen(key));

    spin_lock(&cache_lock);
    hash_for_each_possible(cache, cached, node, hash) {
        if (strcmp(cached->key, key) == 0) {
            spin_unlock(&cache_lock);
            return cached;
        }
    }
    spin_unlock(&cache_lock);
    return NULL;
}

static void cache_put(const char *key, const char *value, size_t value_len, sector_t sector)
{
    struct cached_record *cached;
    u32 hash = djb2_hash(key, strlen(key));

    spin_lock(&cache_lock);

    // Check if the key already exists in the cache
    hash_for_each_possible(cache, cached, node, hash) {
        if (strcmp(cached->key, key) == 0) {
            // Update existing cache entry
            kfree(cached->value);
            cached->value = kmalloc(value_len, GFP_ATOMIC);
            if (cached->value) {
                memcpy(cached->value, value, value_len);
                cached->value_len = value_len;
                cached->sector = sector;
            }
            spin_unlock(&cache_lock);
            return;
        }
    }

    // If the cache is full, remove the first entry we find
    if (cache_count >= CACHE_SIZE) {
        int i;
        struct hlist_node *tmp;
        for (i = 0; i < HASH_SIZE(cache); i++) {
            hlist_for_each_entry_safe(cached, tmp, &cache[i], node) {
                hash_del(&cached->node);
                kfree(cached->value);
                kfree(cached);
                cache_count--;
                goto add_new_entry;
            }
        }
    }

add_new_entry:
    cached = kmalloc(sizeof(*cached), GFP_ATOMIC);
    if (cached) {
        strncpy(cached->key, key, MAX_KEY_SIZE);
        cached->key[MAX_KEY_SIZE - 1] = '\0';
        cached->value = kmalloc(value_len, GFP_ATOMIC);
        if (cached->value) {
            memcpy(cached->value, value, value_len);
            cached->value_len = value_len;
            cached->sector = sector;
            hash_add(cache, &cached->node, hash);
            cache_count++;
        } else {
            kfree(cached);
        }
    }

    spin_unlock(&cache_lock);
}

static int load_record_from_disk(const char *key, char **value, size_t *value_len)
{
    struct record *record;
    struct buffer_head *bh;
    char *buffer;
    int ret = -ENOENT;

    rcu_read_lock();
    hash_for_each_possible_rcu(kv_store, record, hash_node, djb2_hash(key, strlen(key))) {
        if (strcmp(record->key, key) == 0) {
            bh = __bread(bdev, record->sector, BLOCK_SIZE);
            if (!bh) {
                ret = -EIO;
                break;
            }

            buffer = kmalloc(record->value_len, GFP_KERNEL);
            if (!buffer) {
                brelse(bh);
                ret = -ENOMEM;
                break;
            }

            memcpy(buffer, bh->b_data + sizeof(record->key) + sizeof(size_t), record->value_len);
            *value = buffer;
            *value_len = record->value_len;

            brelse(bh);
            ret = 0;
            break;
        }
    }
    rcu_read_unlock();

    return ret;
}

static int search_record(const char *key, char **value, size_t *value_len)
{
    struct cached_record *cached = cache_get(key);
    if (cached) {
        *value = kmalloc(cached->value_len, GFP_KERNEL);
        if (*value) {
            memcpy(*value, cached->value, cached->value_len);
            *value_len = cached->value_len;
            return 0;
        }
    }

    int ret = load_record_from_disk(key, value, value_len);
    if (ret == 0) {
        cache_put(key, *value, *value_len, 0);  // We don't have the sector information here
    }
    return ret;
}

static sector_t find_free_sector(void)
{
    sector_t sector = 0;
    struct buffer_head *bh;
    char *buffer;

    buffer = kmalloc(BLOCK_SIZE, GFP_KERNEL);
    if (!buffer) {
        return -1;
    }

    while (sector * BLOCK_SIZE < i_size_read(bdev->bd_inode)) {
        bh = __bread(bdev, sector, BLOCK_SIZE);
        if (!bh) {
            sector++;
            continue;
        }

        memcpy(buffer, bh->b_data, BLOCK_SIZE);
        brelse(bh);

        if (buffer[0] == '\0') {
            // This sector is free (deleted or never used)
            kfree(buffer);
            return sector;
        }

        sector++;
    }

    // If we've reached here, we need to extend the device
    kfree(buffer);
    return sector;
}

static int insert_or_update_record(const char *key, const char *value, size_t value_len, bool is_partial_update)
{
    struct record *record;
    u32 hash = djb2_hash(key, strlen(key));
    int ret = 0;
    struct buffer_head *bh;
    loff_t device_size;

    mutex_lock(&write_mutex);

    device_size = i_size_read(bdev->bd_inode);

    record = search_record_in_memory(key);
    if (record) {
        // Update existing record
        if (is_partial_update) {
            // Partial update
            size_t new_len = record->value_len + value_len - 1; // -1 to account for null terminator
            char *new_value = krealloc(record->value, new_len, GFP_KERNEL);
            if (!new_value) {
                ret = -ENOMEM;
                goto out;
            }
            strcat(new_value, value);
            new_value[new_len - 1] = '\0';
            record->value = new_value;
            record->value_len = new_len;
        } else {
            // Full update
            char *new_value = krealloc(record->value, value_len + 1, GFP_KERNEL);
            if (!new_value) {
                ret = -ENOMEM;
                goto out;
            }
            memcpy(new_value, value, value_len);
            new_value[value_len] = '\0';
            record->value = new_value;
            record->value_len = value_len + 1; // Include null terminator in length
        }
    } else {
        // Insert new record
        if (atomic_long_read(&total_disk_usage) + value_len > MAX_DISK_USAGE) {
            ret = -ENOSPC;
            goto out;
        }

        record = kmem_cache_alloc(record_cache, GFP_KERNEL);
        if (!record) {
            ret = -ENOMEM;
            goto out;
        }

        strncpy(record->key, key, MAX_KEY_SIZE);
        record->key[MAX_KEY_SIZE - 1] = '\0';
        record->value = kmalloc(value_len + 1, GFP_KERNEL);
        if (!record->value) {
            kmem_cache_free(record_cache, record);
            ret = -ENOMEM;
            goto out;
        }
        memcpy(record->value, value, value_len);
        record->value[value_len] = '\0';
        record->value_len = value_len + 1;

        hash_add_rcu(kv_store, &record->hash_node, hash);
        insert_rb_tree(record);
        atomic_long_add(value_len + 1, &total_disk_usage);
        atomic_inc(&record_count);

        // Find a free sector to write the new record
        sector_t free_sector = find_free_sector();
        if (free_sector == -1) {
            ret = -ENOSPC;
            goto out;
        }

        record->sector = free_sector;
    }

    // Ensure we're not writing beyond the device size
    if ((record->sector + 1) * BLOCK_SIZE > device_size) {
        // Extend the device size if necessary
        i_size_write(bdev->bd_inode, (record->sector + 1) * BLOCK_SIZE);
    }

    // Write to disk
    bh = __getblk(bdev, record->sector, BLOCK_SIZE);
    if (!bh) {
        ret = -EIO;
        goto out;
    }

    memcpy(bh->b_data, record->key, MAX_KEY_SIZE);
    memcpy(bh->b_data + MAX_KEY_SIZE, &record->value_len, sizeof(size_t));
    memcpy(bh->b_data + MAX_KEY_SIZE + sizeof(size_t), record->value, record->value_len);

    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    cache_put(key, record->value, record->value_len, record->sector);

out:
    mutex_unlock(&write_mutex);
    return ret;
}

static void free_record(struct rcu_head *rcu)
{
    struct record *record = container_of(rcu, struct record, rcu);
    kfree(record->value);
    kmem_cache_free(record_cache, record);
}

static int delete_record(const char *key)
{
    struct record *record;
    u32 hash = djb2_hash(key, strlen(key));
    int ret = 0;
    struct buffer_head *bh;

    mutex_lock(&write_mutex);

    record = search_record_in_memory(key);
    if (!record) {
        ret = -ENOENT;
        goto out;
    }

    hash_del_rcu(&record->hash_node);
    rb_erase(&record->tree_node, &records_tree);
    atomic_long_sub(record->value_len, &total_disk_usage);
    atomic_dec(&record_count);

    // Mark the record as deleted on disk
    bh = __getblk(bdev, record->sector, BLOCK_SIZE);
    if (bh) {
        memset(bh->b_data, 0, MAX_KEY_SIZE);  // Set the key to all zeros
        mark_buffer_dirty(bh);
        sync_dirty_buffer(bh);
        brelse(bh);
    }

    call_rcu(&record->rcu, free_record);

    // Remove from cache
    spin_lock(&cache_lock);
    struct cached_record *cached;
    hash_for_each_possible(cache, cached, node, hash) {
        if (strcmp(cached->key, key) == 0) {
            hash_del(&cached->node);
            kfree(cached->value);
            kfree(cached);
            cache_count--;
            break;
        }
    }
    spin_unlock(&cache_lock);

out:
    mutex_unlock(&write_mutex);
    return ret;
}

static void compact_disk(void)
{
    struct record *record;
    struct rb_node *node;
    sector_t read_sector = 0, write_sector = 0;
    char *buffer;
    struct buffer_head *read_bh, *write_bh;

    mutex_lock(&write_mutex);

    buffer = vmalloc(BLOCK_SIZE);
    if (!buffer) {
        printk(KERN_ERR "HPKV: Failed to allocate memory for disk compaction\n");
        goto out;
    }

    while (read_sector * BLOCK_SIZE < i_size_read(bdev->bd_inode)) {
        read_bh = __bread(bdev, read_sector, BLOCK_SIZE);
        if (!read_bh) {
            printk(KERN_ERR "HPKV: Failed to read sector %llu during compaction\n", (unsigned long long)read_sector);
            read_sector++;
            continue;
        }

        // Check if the record is deleted (first byte of key is 0)
        if (read_bh->b_data[0] != '\0') {
            // Record is not deleted, so we need to keep it
            if (read_sector != write_sector) {
                write_bh = __getblk(bdev, write_sector, BLOCK_SIZE);
                if (!write_bh) {
                    printk(KERN_ERR "HPKV: Failed to get block for writing during compaction\n");
                    brelse(read_bh);
                    read_sector++;
                    continue;
                }

                memcpy(write_bh->b_data, read_bh->b_data, BLOCK_SIZE);
                mark_buffer_dirty(write_bh);
                sync_dirty_buffer(write_bh);

                // Update the sector in the in-memory record
                char key[MAX_KEY_SIZE];
                memcpy(key, read_bh->b_data, MAX_KEY_SIZE);
                record = search_record_in_memory(key);
                if (record) {
                    record->sector = write_sector;
                }

                brelse(write_bh);
            }
            write_sector++;
        }

        brelse(read_bh);
        read_sector++;
    }

    // Update the device size
    i_size_write(bdev->bd_inode, write_sector * BLOCK_SIZE);

    // Clear any remaining sectors
    memset(buffer, 0, BLOCK_SIZE);
    while (write_sector < read_sector) {
        write_bh = __getblk(bdev, write_sector, BLOCK_SIZE);
        if (write_bh) {
            memcpy(write_bh->b_data, buffer, BLOCK_SIZE);
            mark_buffer_dirty(write_bh);
            sync_dirty_buffer(write_bh);
            brelse(write_bh);
        }
        write_sector++;
    }

    vfree(buffer);

    printk(KERN_INFO "HPKV: Disk compaction completed. New size: %llu sectors\n", (unsigned long long)write_sector);

out:
    mutex_unlock(&write_mutex);
}

static void compact_work_handler(struct work_struct *work)
{
    long disk_usage = atomic_long_read(&total_disk_usage);
    long device_size = i_size_read(bdev->bd_inode);
    
    // Calculate fragmentation as a percentage (0-100)
    int fragmentation = 0;
    if (device_size > 0) {
        fragmentation = (disk_usage * 100) / device_size;
    }

    if (fragmentation > 30) {  // If more than 30% of the disk is fragmented
        printk(KERN_INFO "HPKV: Starting disk compaction. Fragmentation: %d%%\n", fragmentation);
        compact_disk();
    }

    queue_delayed_work(compact_wq, &compact_work, COMPACT_INTERVAL);
}

static int device_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t device_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset)
{
    struct rb_node *node;
    size_t bytes_read = 0;
    char *temp_buffer;
    loff_t pos = 0;

    read_lock(&rw_lock);

    temp_buffer = kmalloc(MAX_KEY_SIZE + MAX_VALUE_SIZE + 2, GFP_KERNEL);
    if (!temp_buffer) {
        read_unlock(&rw_lock);
        return -ENOMEM;
    }

    for (node = rb_first(&records_tree); node; node = rb_next(node)) {
        struct record *record = rb_entry(node, struct record, tree_node);
        int len = snprintf(temp_buffer, MAX_KEY_SIZE + MAX_VALUE_SIZE + 2, "%s:%s\n", record->key, record->value);
        
        if (pos + len <= *offset) {
            pos += len;
            continue;
        }

        if (pos < *offset) {
            int offset_in_record = *offset - pos;
            len -= offset_in_record;
            if (copy_to_user(user_buffer + bytes_read, temp_buffer + offset_in_record, len)) {
                kfree(temp_buffer);
                read_unlock(&rw_lock);
                return -EFAULT;
            }
        } else {
            if (copy_to_user(user_buffer + bytes_read, temp_buffer, len)) {
                kfree(temp_buffer);
                read_unlock(&rw_lock);
                return -EFAULT;
            }
        }

        bytes_read += len;
        pos += len;

        if (bytes_read >= size)
            break;
    }

    kfree(temp_buffer);
    read_unlock(&rw_lock);
    *offset = pos;
    return bytes_read;
}

static ssize_t device_write(struct file *file, const char __user *user_buffer, size_t size, loff_t *offset)
{
    char *sep;
    int ret;
    bool is_partial_update = false;

    if (size > MAX_KEY_SIZE + MAX_VALUE_SIZE)
        return -EMSGSIZE;

    char *buffer = kmalloc(size + 1, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    if (copy_from_user(buffer, user_buffer, size)) {
        kfree(buffer);
        return -EFAULT;
    }

    buffer[size] = '\0';

    sep = strchr(buffer, ':');
    if (!sep) {
        kfree(buffer);
        return -EINVAL;
    }

    *sep = '\0';

    if (strlen(buffer) >= MAX_KEY_SIZE || strlen(sep + 1) >= MAX_VALUE_SIZE) {
        kfree(buffer);
        return -EMSGSIZE;
    }

    // Check if this is a partial update
    if (sep[1] == '+') {
        is_partial_update = true;
        sep++; // Move past the '+' character
    }

    ret = insert_or_update_record(buffer, sep + 1, strlen(sep + 1) + 1, is_partial_update);
    kfree(buffer);

    if (ret)
        return ret;

    *offset += size;
    return size;
}

static int purge_data(void)
{
    sector_t sector = 0;
    struct buffer_head *bh;
    char *empty_buffer;
    int ret = 0;

    printk(KERN_INFO "HPKV: Purging all data from block device\n");

    empty_buffer = kzalloc(BLOCK_SIZE, GFP_KERNEL);
    if (!empty_buffer) {
        printk(KERN_ERR "HPKV: Failed to allocate memory for purge operation\n");
        return -ENOMEM;
    }

    mutex_lock(&write_mutex);

    while (sector * BLOCK_SIZE < i_size_read(bdev->bd_inode)) {
        bh = __getblk(bdev, sector, BLOCK_SIZE);
        if (!bh) {
            printk(KERN_ERR "HPKV: Failed to get block for purging at sector %llu\n", (unsigned long long)sector);
            ret = -EIO;
            goto out;
        }

        lock_buffer(bh);
        memcpy(bh->b_data, empty_buffer, BLOCK_SIZE);
        set_buffer_uptodate(bh);
        mark_buffer_dirty(bh);
        unlock_buffer(bh);
        sync_dirty_buffer(bh);
        brelse(bh);

        sector++;
    }

    // Clear in-memory data structures
    struct record *record;
    struct rb_node *node, *next;
    for (node = rb_first(&records_tree); node; node = next) {
        next = rb_next(node);
        record = rb_entry(node, struct record, tree_node);
        rb_erase(node, &records_tree);
        hash_del_rcu(&record->hash_node);
        call_rcu(&record->rcu, free_record);
    }
    hash_init(kv_store);
    atomic_long_set(&total_disk_usage, 0);
    atomic_set(&record_count, 0);

    // Clear cache
    spin_lock(&cache_lock);
    struct cached_record *cached;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(cache, bkt, tmp, cached, node) {
        hash_del(&cached->node);
        kfree(cached->value);
        kfree(cached);
    }
    cache_count = 0;
    spin_unlock(&cache_lock);

out:
    mutex_unlock(&write_mutex);
    kfree(empty_buffer);
    printk(KERN_INFO "HPKV: Purge operation completed with status %d\n", ret);
    return ret;
}

static void load_indexes(void)
{
    struct buffer_head *bh;
    sector_t sector = 0;
    char *buffer;
    loff_t device_size;
    bool corruption_detected = false;

    printk(KERN_INFO "HPKV: Entering load_indexes function\n");

    buffer = vmalloc(BLOCK_SIZE);
    if (!buffer) {
        printk(KERN_ERR "HPKV: Failed to allocate buffer for load_indexes\n");
        return;
    }

    device_size = i_size_read(bdev->bd_inode);
    printk(KERN_INFO "HPKV: Device size: %lld bytes\n", device_size);

    if (device_size == 0) {
        printk(KERN_INFO "HPKV: Device is empty. No indexes to load.\n");
        vfree(buffer);
        return;
    }

    while (sector * BLOCK_SIZE < device_size) {
        printk(KERN_INFO "HPKV: Reading sector %llu\n", (unsigned long long)sector);
        
        bh = __bread(bdev, sector, BLOCK_SIZE);
        if (!bh) {
            printk(KERN_ERR "HPKV: Failed to read block at sector %llu\n", (unsigned long long)sector);
            sector++;
            continue;
        }

        memcpy(buffer, bh->b_data, BLOCK_SIZE);
        
        char key[MAX_KEY_SIZE];
        size_t value_len;
        memcpy(key, buffer, sizeof(key));
        memcpy(&value_len, buffer + sizeof(key), sizeof(size_t));

        // Check if the record is deleted (first byte is 0)
        if (key[0] == '\0') {
            printk(KERN_INFO "HPKV: Skipping deleted record at sector %llu\n", (unsigned long long)sector);
            brelse(bh);
            sector++;
            continue;
        }

        printk(KERN_INFO "HPKV: Processing key: %s, value length: %zu\n", key, value_len);

        if (value_len > 0 && value_len <= MAX_VALUE_SIZE) {
            struct record *record = kmem_cache_alloc(record_cache, GFP_KERNEL);
            if (record) {
                strncpy(record->key, key, MAX_KEY_SIZE);
                record->key[MAX_KEY_SIZE - 1] = '\0';  // Ensure null-termination
                record->value = kmalloc(value_len, GFP_KERNEL);
                if (record->value) {
                    memcpy(record->value, buffer + MAX_KEY_SIZE + sizeof(size_t), value_len);
                    record->value_len = value_len;
                    record->sector = sector;
                
                    u32 hash = djb2_hash(key, strlen(key));
                    hash_add_rcu(kv_store, &record->hash_node, hash);
                    insert_rb_tree(record);
                    atomic_long_add(value_len, &total_disk_usage);
                    atomic_inc(&record_count);
                
                    printk(KERN_INFO "HPKV: Added record for key: %s\n", key);
                } else {
                    printk(KERN_ERR "HPKV: Failed to allocate memory for record value\n");
                    kmem_cache_free(record_cache, record);
                }
            } else {
                printk(KERN_ERR "HPKV: Failed to allocate memory for record\n");
            }
        } else {
            printk(KERN_WARNING "HPKV: Invalid record found at sector %llu. Key: %s, Value length: %zu\n", 
                   (unsigned long long)sector, key, value_len);
            corruption_detected = true;
            break;  // Stop processing further to avoid potential issues with corrupted data
        }

        brelse(bh);
        sector++;
    }

    vfree(buffer);

    if (corruption_detected) {
        printk(KERN_WARNING "HPKV: Corruption detected. Initiating purge operation.\n");
        purge_data();
        printk(KERN_INFO "HPKV: Purge completed. Device is now empty.\n");
    } else {
        printk(KERN_INFO "HPKV: Exiting load_indexes function. Processed %llu sectors\n", (unsigned long long)sector);
    }
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    char key[MAX_KEY_SIZE];
    char *value;
    size_t value_len;
    int ret;

    switch (cmd) {
        case 0:  // Get by exact key
            if (copy_from_user(key, (char __user *)arg, MAX_KEY_SIZE))
                return -EFAULT;
            
            key[MAX_KEY_SIZE - 1] = '\0';
            ret = search_record(key, &value, &value_len);
            if (ret == 0) {
                if (copy_to_user((void __user *)arg, value, value_len)) {
                    kfree(value);
                    return -EFAULT;
                }
                kfree(value);
                return 0;
            }
            return ret;
        
        case 1:  // Delete by key
            if (copy_from_user(key, (char __user *)arg, MAX_KEY_SIZE))
                return -EFAULT;
            
            key[MAX_KEY_SIZE - 1] = '\0';
            return delete_record(key);

        case 2:  // Partial update
            if (copy_from_user(key, (char __user *)arg, MAX_KEY_SIZE))
                return -EFAULT;
            
            key[MAX_KEY_SIZE - 1] = '\0';
            if (copy_from_user(value, (char __user *)(arg + MAX_KEY_SIZE), MAX_VALUE_SIZE))
                return -EFAULT;
            
            return insert_or_update_record(key, value, strlen(value), true);

        case 3:  // Purge all data
            return purge_data();

        default:
            return -ENOTTY;
    }
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = device_read,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_release
};

static int hpkv_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Total records: %d\n", atomic_read(&record_count));
    seq_printf(m, "Total disk usage: %ld bytes\n", atomic_long_read(&total_disk_usage));
    return 0;
}

static int hpkv_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, hpkv_proc_show, NULL);
}

static const struct proc_ops hpkv_proc_fops = {
    .proc_open = hpkv_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int initialize_empty_device(void)
{
    struct buffer_head *bh;
    char *empty_buffer;
    int ret = 0;

    empty_buffer = kzalloc(BLOCK_SIZE, GFP_KERNEL);
    if (!empty_buffer) {
        printk(KERN_ERR "HPKV: Failed to allocate memory for device initialization\n");
        return -ENOMEM;
    }

    // Write an empty block to sector 0
    bh = __getblk(bdev, 0, BLOCK_SIZE);
    if (!bh) {
        printk(KERN_ERR "HPKV: Failed to get block for initialization\n");
        kfree(empty_buffer);
        return -EIO;
    }

    memcpy(bh->b_data, empty_buffer, BLOCK_SIZE);
    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    // Set the device size to one block
    i_size_write(bdev->bd_inode, BLOCK_SIZE);

    kfree(empty_buffer);
    return ret;
}

static int __init hpkv_init(void)
{
    int ret;

    printk(KERN_INFO "HPKV: Initializing module\n");
    printk(KERN_INFO "HPKV: Mount path received: %s\n", mount_path);

    major_num = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ALERT "HPKV: Failed to register a major number\n");
        return major_num;
    }

    record_cache = kmem_cache_create("hpkv_record", sizeof(struct record), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!record_cache) {
        printk(KERN_ALERT "HPKV: Failed to create record cache\n");
        unregister_chrdev(major_num, DEVICE_NAME);
        return -ENOMEM;
    }
    printk(KERN_INFO "HPKV: Record cache created successfully\n");

    hash_init(kv_store);
    printk(KERN_INFO "HPKV: Hash table initialized\n");

    printk(KERN_INFO "HPKV: Attempting to open block device: %s\n", mount_path);
    bdev = blkdev_get_by_path(mount_path, FMODE_READ | FMODE_WRITE, THIS_MODULE);
    if (IS_ERR(bdev)) {
        printk(KERN_ALERT "HPKV: Failed to open block device, error %ld\n", PTR_ERR(bdev));
        kmem_cache_destroy(record_cache);
        unregister_chrdev(major_num, DEVICE_NAME);
        return PTR_ERR(bdev);
    }
    printk(KERN_INFO "HPKV: Block device opened successfully\n");

    // Check if the device is valid and get its size
    if (!bdev->bd_disk) {
        printk(KERN_ALERT "HPKV: Invalid block device\n");
        ret = -EINVAL;
        goto error_exit;
    }

    loff_t device_size = i_size_read(bdev->bd_inode);
    if (device_size == 0) {
        printk(KERN_INFO "HPKV: Block device is empty. Initializing with empty state.\n");
        // Initialize the device with a minimal structure if needed
        ret = initialize_empty_device();
        if (ret < 0) {
            goto error_exit;
        }
    } else {
        printk(KERN_INFO "HPKV: Block device contains data. Loading indexes...\n");
        load_indexes();
        // After load_indexes, check if a purge was necessary
        if (atomic_read(&record_count) == 0) {
            printk(KERN_INFO "HPKV: No valid records found or purge was performed. Starting with empty state.\n");
        } else {
            printk(KERN_INFO "HPKV: Finished loading indexes. Total records: %d\n", atomic_read(&record_count));
        }
    }

    printk(KERN_INFO "HPKV: Creating proc entry\n");
    proc_create(PROC_ENTRY, 0, NULL, &hpkv_proc_fops);

    compact_wq = create_singlethread_workqueue("hpkv_compact");
    if (!compact_wq) {
        printk(KERN_ALERT "HPKV: Failed to create compaction workqueue\n");
        ret = -ENOMEM;
        goto error_exit;
    }

    INIT_DELAYED_WORK(&compact_work, compact_work_handler);
    queue_delayed_work(compact_wq, &compact_work, COMPACT_INTERVAL);

    printk(KERN_INFO "HPKV: Module loaded successfully\n");
    printk(KERN_INFO "HPKV: Registered with major number %d\n", major_num);
    return 0;

error_exit:
    if (bdev) {
        blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
    }
    kmem_cache_destroy(record_cache);
    unregister_chrdev(major_num, DEVICE_NAME);
    return ret;
}

static void __exit hpkv_exit(void)
{
    struct record *record;
    struct rb_node *node;

    cancel_delayed_work_sync(&compact_work);
    destroy_workqueue(compact_wq);

    while ((node = rb_first(&records_tree))) {
        record = rb_entry(node, struct record, tree_node);
        rb_erase(node, &records_tree);
        hash_del(&record->hash_node);
        free_record(&record->rcu);
    }

    if (bdev) {
        blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
    }

    // Clear cache
    spin_lock(&cache_lock);
    struct cached_record *cached;
    struct hlist_node *tmp;
    int bkt;
    hash_for_each_safe(cache, bkt, tmp, cached, node) {
        hash_del(&cached->node);
        kfree(cached->value);
        kfree(cached);
    }
    spin_unlock(&cache_lock);

    remove_proc_entry(PROC_ENTRY, NULL);
    kmem_cache_destroy(record_cache);
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "HPKV: Module unloaded\n");
}

module_init(hpkv_init);
module_exit(hpkv_exit);
