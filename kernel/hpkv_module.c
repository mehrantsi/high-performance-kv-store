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
#include <linux/percpu-rwsem.h>
#include <linux/percpu.h>
#include <linux/rculist.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#define DEVICE_NAME "hpkv"
#define MAX_KEY_SIZE 256
#define MAX_VALUE_SIZE 1000
#define HPKV_HASH_BITS (20) // 2^20 = 1,048,576 buckets
#define MAX_DISK_USAGE (1UL << 32) // 4 GB max disk usage
#define BLOCK_SIZE 4096
#define PROC_ENTRY "hpkv_stats"
#define CACHE_SIZE 1000
#define COMPACT_INTERVAL (120 * HZ) // Run compaction every 120 seconds
#define HPKV_SIGNATURE "HPKV_V1"
#define HPKV_SIGNATURE_SIZE 8
#define HPKV_METADATA_BLOCK 0
#define WRITE_BUFFER_SIZE 1024
#define WRITE_BUFFER_FLUSH_INTERVAL (HZ * 5) // 5 seconds
#define MAX_DEVICE_SIZE (1ULL << 40)  // 1 TB, adjust as needed

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mehran Toosi");
MODULE_DESCRIPTION("High performance KV store kernel module, with advanced features");
MODULE_VERSION("1.0");

// Function prototypes
static u32 djb2_hash(const char *str, size_t len);
static struct record *search_record_in_memory(const char *key);
static void insert_rb_tree(struct record *record);
static struct cached_record *cache_get(const char *key);
static void cache_put(const char *key, const char *value, size_t value_len, sector_t sector);
static int load_record_from_disk(const char *key, char **value, size_t *value_len);
static void record_free_rcu(struct rcu_head *head);
static struct record *record_find_rcu(const char *key);
static struct record *find_record_in_write_buffer(const char *key);
static int search_record(const char *key, char **value, size_t *value_len);
static int write_buffer_size(void);
static sector_t find_free_sector(void);
static int update_metadata(void);
static int insert_or_update_record(const char *key, const char *value, size_t value_len, bool is_partial_update);
static int delete_record(const char *key);
static int write_buffer_worker(void *data);
static void compact_disk(void);
static int calculate_fragmentation(void);
static void compact_work_handler(struct work_struct *work);
static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset);
static ssize_t device_write(struct file *file, const char __user *user_buffer, size_t size, loff_t *offset);
static int purge_data(void);
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int hpkv_proc_show(struct seq_file *m, void *v);
static int hpkv_proc_open(struct inode *inode, struct file *file);
static int initialize_empty_device(void);
static bool is_zero_buffer(const void *buf, size_t size);
static bool is_disk_empty(struct block_device *bdev);
static void flush_write_buffer(void);
static void write_record_to_disk(struct record *record);

static int major_num;
static struct kmem_cache *record_cache;
static DEFINE_PER_CPU(struct llist_head, record_free_list);
static struct percpu_rw_semaphore rw_sem;

struct hpkv_metadata {
    char signature[HPKV_SIGNATURE_SIZE];
    uint64_t total_records;
    uint64_t total_size;
    uint32_t version;
};

struct record {
    char key[MAX_KEY_SIZE];
    char *value;
    size_t value_len;
    struct hlist_node hash_node;
    struct rb_node tree_node;
    struct rcu_head rcu;
    struct llist_node list_node;
    sector_t sector;
    atomic_t refcount;
};

struct cached_record {
    char key[MAX_KEY_SIZE];
    char *value;
    size_t value_len;
    sector_t sector;
    struct hlist_node node;
};

struct write_buffer_entry {
    struct record *record;
    struct list_head list;
};

static LIST_HEAD(write_buffer);
static DEFINE_SPINLOCK(write_buffer_lock);
static struct task_struct *write_buffer_thread;
static wait_queue_head_t write_buffer_wait;
static bool write_buffer_exit = false;

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

static bool initialize_if_empty = true;
module_param(initialize_if_empty, bool, 0644);
MODULE_PARM_DESC(initialize_if_empty, "Initialize the device if it's empty (default: true)");

static struct workqueue_struct *compact_wq;
static struct delayed_work compact_work;

#define HPKV_LOG_EMERG   0
#define HPKV_LOG_ALERT   1
#define HPKV_LOG_CRIT    2
#define HPKV_LOG_ERR     3
#define HPKV_LOG_WARNING 4
#define HPKV_LOG_NOTICE  5
#define HPKV_LOG_INFO    6
#define HPKV_LOG_DEBUG   7

static int log_level = HPKV_LOG_WARNING;
module_param(log_level, int, 0644);
MODULE_PARM_DESC(log_level, "Logging level (0-7, default: 4)");

#define hpkv_log(level, fmt, ...) \
    do { \
        if (level <= log_level) { \
            const char *kern_level; \
            switch (level) { \
                case HPKV_LOG_EMERG:   kern_level = KERN_EMERG; break; \
                case HPKV_LOG_ALERT:   kern_level = KERN_ALERT; break; \
                case HPKV_LOG_CRIT:    kern_level = KERN_CRIT; break; \
                case HPKV_LOG_ERR:     kern_level = KERN_ERR; break; \
                case HPKV_LOG_WARNING: kern_level = KERN_WARNING; break; \
                case HPKV_LOG_NOTICE:  kern_level = KERN_NOTICE; break; \
                case HPKV_LOG_INFO:    kern_level = KERN_INFO; break; \
                case HPKV_LOG_DEBUG:   kern_level = KERN_DEBUG; break; \
                default:               kern_level = KERN_DEFAULT; break; \
            } \
            printk("%sHPKV: %s:%d: " fmt, kern_level, __func__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

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

static void record_free_rcu(struct rcu_head *head)
{
    struct record *record = container_of(head, struct record, rcu);
    if (record) {
        if (record->value) {
            kfree(record->value);
            record->value = NULL;
        }
        kmem_cache_free(record_cache, record);
    }
}


static struct record *record_find_rcu(const char *key)
{
    struct record *record;
    u32 hash = djb2_hash(key, strlen(key));

    hash_for_each_possible_rcu(kv_store, record, hash_node, hash) {
        if (strcmp(record->key, key) == 0)
            return record;
    }
    return NULL;
}

static struct record *find_record_in_write_buffer(const char *key)
{
    struct write_buffer_entry *entry;

    spin_lock(&write_buffer_lock);
    list_for_each_entry(entry, &write_buffer, list) {
        if (strcmp(entry->record->key, key) == 0) {
            spin_unlock(&write_buffer_lock);
            return entry->record;
        }
    }
    spin_unlock(&write_buffer_lock);
    return NULL;
}

static int search_record(const char *key, char **value, size_t *value_len)
{
    struct record *record;
    struct write_buffer_entry *entry;
    int ret = -ENOENT;

    // First, check the write buffer
    spin_lock(&write_buffer_lock);
    list_for_each_entry_reverse(entry, &write_buffer, list) {
        if (strcmp(entry->record->key, key) == 0) {
            *value = kmalloc(entry->record->value_len + 1, GFP_ATOMIC);
            if (!*value) {
                spin_unlock(&write_buffer_lock);
                return -ENOMEM;
            }
            memcpy(*value, entry->record->value, entry->record->value_len + 1);
            *value_len = entry->record->value_len;
            spin_unlock(&write_buffer_lock);
            return 0;
        }
    }
    spin_unlock(&write_buffer_lock);

    // If not found in write buffer, check in-memory structures
    rcu_read_lock();
    record = record_find_rcu(key);
    if (record) {
        *value = kmalloc(record->value_len + 1, GFP_ATOMIC);
        if (!*value) {
            rcu_read_unlock();
            return -ENOMEM;
        }
        memcpy(*value, record->value, record->value_len + 1);
        *value_len = record->value_len;
        ret = 0;
    }
    rcu_read_unlock();

    if (ret == 0) {
        cache_put(key, *value, *value_len, record->sector);
        return ret;
    }

    // If not found in memory, attempt to load from disk
    ret = load_record_from_disk(key, value, value_len);
    if (ret == 0) {
        cache_put(key, *value, *value_len, 0);
    }

    return ret;
}

static int write_buffer_size(void)
{
    int count = 0;
    struct write_buffer_entry *entry;

    spin_lock(&write_buffer_lock);
    list_for_each_entry(entry, &write_buffer, list) {
        count++;
    }
    spin_unlock(&write_buffer_lock);

    return count;
}

static sector_t find_free_sector(void)
{
    sector_t sector = 1;
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

static int update_metadata(void)
{
    struct buffer_head *bh;
    struct hpkv_metadata metadata;
    int ret = 0;

    bh = __bread(bdev, HPKV_METADATA_BLOCK, BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to read metadata block for update\n");
        return -EIO;
    }

    memcpy(&metadata, bh->b_data, sizeof(struct hpkv_metadata));

    // Update the fields
    metadata.total_records = atomic_read(&record_count);
    metadata.total_size = atomic_long_read(&total_disk_usage);

    // Write back the updated metadata
    memcpy(bh->b_data, &metadata, sizeof(struct hpkv_metadata));
    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    hpkv_log(HPKV_LOG_INFO, "Updated metadata - Total records: %llu, Total size: %llu bytes\n",
           metadata.total_records, metadata.total_size);

    return ret;
}

static int insert_or_update_record(const char *key, const char *value, size_t value_len, bool is_partial_update)
{
    struct record *new_record, *old_record;
    struct write_buffer_entry *wb_entry;
    int ret = 0;
    u32 hash = djb2_hash(key, strlen(key));

    new_record = kmem_cache_alloc(record_cache, GFP_KERNEL);
    if (!new_record)
        return -ENOMEM;

    // Add a size check before allocation
    if (value_len > MAX_VALUE_SIZE) {
        kmem_cache_free(record_cache, new_record);
        return -EINVAL;
    }

    new_record->value = kmalloc(value_len + 1, GFP_KERNEL);
    if (!new_record->value) {
        kmem_cache_free(record_cache, new_record);
        return -ENOMEM;
    }

    strncpy(new_record->key, key, MAX_KEY_SIZE);
    new_record->key[MAX_KEY_SIZE - 1] = '\0';

    // Update in-memory data structures
    percpu_down_write(&rw_sem);

    old_record = record_find_rcu(key);
    if (old_record && is_partial_update) {
        // Perform partial update
        size_t new_len = old_record->value_len + value_len;
        char *new_value = kmalloc(new_len + 1, GFP_KERNEL);
        if (!new_value) {
            percpu_up_write(&rw_sem);
            kmem_cache_free(record_cache, new_record);
            return -ENOMEM;
        }
        memcpy(new_value, old_record->value, old_record->value_len);
        memcpy(new_value + old_record->value_len, value, value_len);
        new_value[new_len] = '\0';

        new_record->value = new_value;
        new_record->value_len = new_len;
    } else {
        // Regular update or new record
        memcpy(new_record->value, value, value_len);
        new_record->value[value_len] = '\0';
        new_record->value_len = value_len;
    }

    if (old_record) {
        // Remove old record
        hash_del_rcu(&old_record->hash_node);
        rb_erase(&old_record->tree_node, &records_tree);
        atomic_long_sub(old_record->value_len, &total_disk_usage);
        call_rcu(&old_record->rcu, record_free_rcu);
    } else {
        atomic_inc(&record_count);
    }

    // Insert new record
    hash_add_rcu(kv_store, &new_record->hash_node, hash);
    insert_rb_tree(new_record);
    atomic_long_add(new_record->value_len, &total_disk_usage);

    percpu_up_write(&rw_sem);

    // Prepare and add to write buffer after updating in-memory structures
    wb_entry = kmalloc(sizeof(*wb_entry), GFP_KERNEL);
    if (!wb_entry) {
        kfree(new_record->value);
        kmem_cache_free(record_cache, new_record);
        return -ENOMEM;
    }
    wb_entry->record = new_record;

    spin_lock(&write_buffer_lock);
    list_add_tail(&wb_entry->list, &write_buffer);
    spin_unlock(&write_buffer_lock);

    wake_up(&write_buffer_wait);

    // Update cache with the new value
    cache_put(key, new_record->value, new_record->value_len, 0);

    // Update metadata
    ret = update_metadata();
    if (ret < 0) {
        hpkv_log(HPKV_LOG_ERR, "Failed to update metadata after insert/update\n");
    }

    return ret;
}

static int delete_record(const char *key)
{
    struct record *record;
    u32 hash = djb2_hash(key, strlen(key));
    int ret = 0;
    struct buffer_head *bh;
    struct write_buffer_entry *entry, *temp;

    // First, check if the record is in the write buffer
    spin_lock(&write_buffer_lock);
    list_for_each_entry_safe(entry, temp, &write_buffer, list) {
        if (strcmp(entry->record->key, key) == 0) {
            // Remove from write buffer
            list_del(&entry->list);
            // Free the record
            kfree(entry->record->value);
            kmem_cache_free(record_cache, entry->record);
            kfree(entry);
            spin_unlock(&write_buffer_lock);

            // Update in-memory structures
            percpu_down_write(&rw_sem);
            hash_del_rcu(&entry->record->hash_node);
            rb_erase(&entry->record->tree_node, &records_tree);
            atomic_long_sub(entry->record->value_len, &total_disk_usage);
            atomic_dec(&record_count);
            percpu_up_write(&rw_sem);

            ret = update_metadata();
            if (ret < 0) {
                hpkv_log(HPKV_LOG_ERR, "Failed to update metadata after deletion\n");
            }

            return ret;
        }
    }
    spin_unlock(&write_buffer_lock);

    // Proceed with existing delete logic
    percpu_down_write(&rw_sem);

    rcu_read_lock();
    record = record_find_rcu(key);
    if (!record) {
        ret = -ENOENT;
        goto out_unlock;
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

    call_rcu(&record->rcu, record_free_rcu);

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

    ret = update_metadata();
    if (ret < 0) {
        hpkv_log(HPKV_LOG_ERR, "Failed to update metadata after deletion\n");
    }

out_unlock:
    rcu_read_unlock();
    percpu_up_write(&rw_sem);
    return ret;
}

static void write_record_to_disk(struct record *record)
{
    struct buffer_head *bh;
    loff_t device_size;

    device_size = i_size_read(bdev->bd_inode);

    // Find a free sector (ensure thread safety)
    record->sector = find_free_sector();
    if (record->sector == -1) {
        hpkv_log(HPKV_LOG_ERR, "No free sector available for writing\n");
        return;
    }

    // Check if we need to extend the device
    if ((record->sector + 1) * BLOCK_SIZE > device_size) {
        loff_t new_size = (record->sector + 1) * BLOCK_SIZE;
        
        // Check if the new size exceeds the maximum allowed size
        if (new_size > MAX_DEVICE_SIZE) {
            hpkv_log(HPKV_LOG_ERR, "Cannot extend device beyond maximum size of %llu bytes\n", MAX_DEVICE_SIZE);
            return;
        }

        // Extend the device size
        i_size_write(bdev->bd_inode, new_size);
        hpkv_log(HPKV_LOG_INFO, "Extended device size to %lld bytes\n", new_size);
    }

    // Write to disk
    bh = __getblk(bdev, record->sector, BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer head for writing\n");
        return;
    }

    lock_buffer(bh);
    memcpy(bh->b_data, record->key, MAX_KEY_SIZE);
    memcpy(bh->b_data + MAX_KEY_SIZE, &record->value_len, sizeof(size_t));
    memcpy(bh->b_data + MAX_KEY_SIZE + sizeof(size_t), record->value, record->value_len);
    set_buffer_uptodate(bh);
    mark_buffer_dirty(bh);
    unlock_buffer(bh);

    if (sync_dirty_buffer(bh) < 0) {
        hpkv_log(HPKV_LOG_ERR, "Failed to sync buffer to disk\n");
    }

    brelse(bh);
}

static void flush_write_buffer(void)
{
    struct write_buffer_entry *entry, *tmp;
    LIST_HEAD(local_list);

    spin_lock(&write_buffer_lock);
    list_splice_init(&write_buffer, &local_list);
    spin_unlock(&write_buffer_lock);

    list_for_each_entry_safe(entry, tmp, &local_list, list) {
        list_del(&entry->list);
        write_record_to_disk(entry->record);
        kmem_cache_free(record_cache, entry->record);
        kfree(entry);
    }
}

static int write_buffer_worker(void *data)
{
    struct write_buffer_entry *entry;
    unsigned long next_flush = jiffies + WRITE_BUFFER_FLUSH_INTERVAL;

    while (!kthread_should_stop()) {
        if (time_after(jiffies, next_flush) || write_buffer_size() >= WRITE_BUFFER_SIZE) {
            while (true) {
                spin_lock(&write_buffer_lock);
                if (list_empty(&write_buffer)) {
                    spin_unlock(&write_buffer_lock);
                    break;
                }
                entry = list_first_entry(&write_buffer, struct write_buffer_entry, list);
                list_del(&entry->list);
                spin_unlock(&write_buffer_lock);

                // Write the record to disk
                write_record_to_disk(entry->record);

                // Free the entry
                kmem_cache_free(record_cache, entry->record);
                kfree(entry);
            }

            next_flush = jiffies + WRITE_BUFFER_FLUSH_INTERVAL;
        }

        wait_event_interruptible_timeout(write_buffer_wait, 
                                         kthread_should_stop() || write_buffer_size() >= WRITE_BUFFER_SIZE,
                                         WRITE_BUFFER_FLUSH_INTERVAL);
    }

    return 0;
}

static void compact_disk(void)
{
    // Flush write buffer before compaction
    flush_write_buffer();

    struct record *record;
    struct rb_node *node;
    sector_t read_sector = 1, write_sector = 1;
    char *buffer;
    struct buffer_head *read_bh, *write_bh;
    sector_t total_sectors;

    percpu_down_write(&rw_sem);

    total_sectors = i_size_read(bdev->bd_inode) / BLOCK_SIZE;
    hpkv_log(HPKV_LOG_INFO, "Starting disk compaction. Total sectors: %llu\n", (unsigned long long)total_sectors);

    buffer = vmalloc(BLOCK_SIZE);
    if (!buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer for disk compaction\n");
        goto out;
    }

    while (read_sector < total_sectors) {
        read_bh = __bread(bdev, read_sector, BLOCK_SIZE);
        if (!read_bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read sector %llu during compaction\n", (unsigned long long)read_sector);
            read_sector++;
            continue;
        }

        // Check if the record is deleted (first byte of key is 0)
        if (read_bh->b_data[0] != '\0') {
            // Record is not deleted, so we need to keep it
            if (read_sector != write_sector) {
                write_bh = __getblk(bdev, write_sector, BLOCK_SIZE);
                if (!write_bh) {
                    hpkv_log(HPKV_LOG_ERR, "Failed to get block for writing during compaction\n");
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

    vfree(buffer);

    // Truncate the device to the new size
    sector_t new_size = write_sector * BLOCK_SIZE;
    i_size_write(bdev->bd_inode, new_size);
    sync_blockdev(bdev);

    hpkv_log(HPKV_LOG_INFO, "Disk compaction completed. New size: %llu sectors\n", (unsigned long long)write_sector);

out:
    percpu_up_write(&rw_sem);
}

static int calculate_fragmentation(void)
{
    struct record *record;
    struct rb_node *node;
    sector_t next_expected_sector = 1;  // Start from sector 1
    sector_t current_sector;
    sector_t total_sectors = i_size_read(bdev->bd_inode) / BLOCK_SIZE;
    long total_used_space = 0;
    long total_empty_space = 0;

    rcu_read_lock();
    for (node = rb_first(&records_tree); node; node = rb_next(node)) {
        record = rb_entry(node, struct record, tree_node);
        current_sector = READ_ONCE(record->sector);

        if (current_sector > next_expected_sector) {
            total_empty_space += (current_sector - next_expected_sector) * BLOCK_SIZE;
        }

        // Calculate the number of sectors this record occupies
        sector_t record_sectors = (READ_ONCE(record->value_len) + BLOCK_SIZE - 1) / BLOCK_SIZE;
        total_used_space += record_sectors * BLOCK_SIZE;
        next_expected_sector = current_sector + record_sectors;

        if (next_expected_sector > total_sectors) {
            hpkv_log(HPKV_LOG_WARNING, "Record extends beyond device size at sector %llu\n", (unsigned long long)current_sector);
            next_expected_sector = total_sectors;
            break;
        }
    }
    rcu_read_unlock();

    // Add any empty space at the end of the device
    if (total_sectors > next_expected_sector) {
        total_empty_space += (total_sectors - next_expected_sector) * BLOCK_SIZE;
    }

    long total_space = total_used_space + total_empty_space;

    // Update total_disk_usage if it's inconsistent
    long current_disk_usage = atomic_long_read(&total_disk_usage);
    if (total_used_space != current_disk_usage) {
        hpkv_log(HPKV_LOG_WARNING, "Inconsistency detected in disk usage. Calculated: %ld, Stored: %ld. Updating.\n", 
               total_used_space, current_disk_usage);
        atomic_long_set(&total_disk_usage, total_used_space);
    }

    // Calculate fragmentation percentage
    int fragmentation_percentage = 0;
    if (total_space > 0) {
        fragmentation_percentage = (int)((total_empty_space * 100LL) / total_space);
    }

    hpkv_log(HPKV_LOG_INFO, "Fragmentation: %d%% (Empty: %ld bytes, Used: %ld bytes, Total: %ld bytes)\n", 
           fragmentation_percentage, total_empty_space, total_used_space, total_space);

    return fragmentation_percentage;
}

static void compact_work_handler(struct work_struct *work)
{
    int fragmentation = calculate_fragmentation();
    long disk_usage = atomic_long_read(&total_disk_usage);
    long device_size = i_size_read(bdev->bd_inode);

    hpkv_log(HPKV_LOG_INFO, "Current fragmentation: %d%% (total used: %ld bytes, device size: %ld bytes)\n", 
           fragmentation, disk_usage, device_size);

    if (fragmentation > 30) {  // If more than 30% of the total space is empty (fragmented)
        hpkv_log(HPKV_LOG_INFO, "Starting disk compaction. Fragmentation: %d%%\n", fragmentation);
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

    percpu_down_read(&rw_sem);
    rcu_read_lock();

    temp_buffer = kmalloc(MAX_KEY_SIZE + MAX_VALUE_SIZE + 2, GFP_KERNEL);
    if (!temp_buffer) {
        rcu_read_unlock();
        percpu_up_read(&rw_sem);
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
                rcu_read_unlock();
                percpu_up_read(&rw_sem);
                return -EFAULT;
            }
        } else {
            if (copy_to_user(user_buffer + bytes_read, temp_buffer, len)) {
                kfree(temp_buffer);
                rcu_read_unlock();
                percpu_up_read(&rw_sem);
                return -EFAULT;
            }
        }

        bytes_read += len;
        pos += len;

        if (bytes_read >= size)
            break;
    }

    kfree(temp_buffer);
    rcu_read_unlock();
    percpu_up_read(&rw_sem);
    *offset = pos;
    return bytes_read;
}

static ssize_t device_write(struct file *file, const char __user *user_buffer, size_t size, loff_t *offset)
{
    if (size > MAX_KEY_SIZE + MAX_VALUE_SIZE + 1)  // +1 for the separator
        return -EMSGSIZE;

    char *buffer = kmalloc(size + 1, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    if (copy_from_user(buffer, user_buffer, size)) {
        kfree(buffer);
        return -EFAULT;
    }

    buffer[size] = '\0';

    char *sep = strchr(buffer, ':');
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
    bool is_partial_update = false;
    if (sep[1] == '+') {
        is_partial_update = true;
        sep++; // Move past the '+' character
    }

    int ret = insert_or_update_record(buffer, sep + 1, strlen(sep + 1), is_partial_update);
    kfree(buffer);

    if (ret)
        return ret;

    *offset += size;
    return size;
}

static int purge_data(void)
{
    sector_t sector = 1;
    struct buffer_head *bh;
    char *empty_buffer;
    int ret = 0;
    struct record *record, *tmp;
    struct rb_node *node;

    percpu_down_write(&rw_sem);

    hpkv_log(HPKV_LOG_INFO, "Purging all data from block device\n");

    // Clear the write buffer
    flush_write_buffer();

    empty_buffer = kzalloc(BLOCK_SIZE, GFP_KERNEL);
    if (!empty_buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for purge operation\n");
        ret = -ENOMEM;
        goto out;
    }

    while (sector * BLOCK_SIZE < i_size_read(bdev->bd_inode)) {
        bh = __getblk(bdev, sector, BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to get block for purging at sector %llu\n", (unsigned long long)sector);
            ret = -EIO;
            goto out_free_buffer;
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
    rcu_read_lock();
    for (node = rb_first(&records_tree); node; node = rb_next(node)) {
        record = rb_entry(node, struct record, tree_node);
        rb_erase(&record->tree_node, &records_tree);
        hash_del_rcu(&record->hash_node);
    }
    rcu_read_unlock();

    // Free the records after RCU grace period
    synchronize_rcu();
    rbtree_postorder_for_each_entry_safe(record, tmp, &records_tree, tree_node) {
        if (record->value) {
            kfree(record->value);
            record->value = NULL;
        }
        kmem_cache_free(record_cache, record);
    }

    // Reset the tree root
    records_tree = RB_ROOT;

    // Clear hash table
    hash_init(kv_store);

    atomic_long_set(&total_disk_usage, 0);
    atomic_set(&record_count, 0);

    // Clear cache
    spin_lock(&cache_lock);
    struct cached_record *cached;
    struct hlist_node *tmp_node;
    int bkt;
    hash_for_each_safe(cache, bkt, tmp_node, cached, node) {
        hash_del(&cached->node);
        kfree(cached->value);
        kfree(cached);
    }
    cache_count = 0;
    spin_unlock(&cache_lock);

    ret = update_metadata();
    if (ret < 0) {
        hpkv_log(HPKV_LOG_ERR, "Failed to update metadata after purge\n");
    }

out_free_buffer:
    kfree(empty_buffer);
out:
    percpu_up_write(&rw_sem);
    hpkv_log(HPKV_LOG_INFO, "Purge operation completed with status %d\n", ret);
    return ret;
}

static int load_indexes(void)
{
    struct buffer_head *bh;
    struct hpkv_metadata metadata;
    sector_t sector = 1;  // Start from sector 1, as sector 0 is reserved for metadata
    char *buffer;
    loff_t device_size;
    bool corruption_detected = false;
    int ret = 0;

    percpu_down_write(&rw_sem);

    hpkv_log(HPKV_LOG_INFO, "Loading indexes\n");

    // Read the metadata block (sector 0)
    bh = __bread(bdev, HPKV_METADATA_BLOCK, BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to read metadata block\n");
        ret = -EIO;
        goto out;
    }

    memcpy(&metadata, bh->b_data, sizeof(struct hpkv_metadata));
    brelse(bh);
    if (memcmp(metadata.signature, HPKV_SIGNATURE, HPKV_SIGNATURE_SIZE) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Invalid signature found. This disk is not formatted for HPKV use.\n");
        ret = -EINVAL;
        goto out;
    }

    hpkv_log(HPKV_LOG_INFO, "Valid signature found. Loading existing data.\n");
    hpkv_log(HPKV_LOG_INFO, "Total records: %llu, Total size: %llu bytes\n", 
           metadata.total_records, metadata.total_size);

    device_size = i_size_read(bdev->bd_inode);
    hpkv_log(HPKV_LOG_INFO, "Device size: %lld bytes\n", device_size);

    buffer = vmalloc(BLOCK_SIZE);
    if (!buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer for load_indexes\n");
        ret = -ENOMEM;
        goto out;
    }

    while (sector * BLOCK_SIZE < device_size) {
        hpkv_log(HPKV_LOG_INFO, "Reading sector %llu\n", (unsigned long long)sector);
        
        bh = __bread(bdev, sector, BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read block at sector %llu\n", (unsigned long long)sector);
            sector++;
            continue;
        }

        memcpy(buffer, bh->b_data, BLOCK_SIZE);
        
        char key[MAX_KEY_SIZE];
        size_t value_len;
        memcpy(key, buffer, sizeof(key));
        memcpy(&value_len, buffer + sizeof(key), sizeof(size_t));

        hpkv_log(HPKV_LOG_INFO, "Processing key: %s, value length: %zu\n", key, value_len);

        if (key[0] != '\0' && value_len > 0 && value_len <= MAX_VALUE_SIZE) {
            struct record *record = kmem_cache_alloc(record_cache, GFP_KERNEL);
            if (record) {
                strncpy(record->key, key, MAX_KEY_SIZE);
                record->key[MAX_KEY_SIZE - 1] = '\0';  // Ensure null-termination
                record->value = kmalloc(value_len + 1, GFP_KERNEL);
                if (record->value) {
                    memcpy(record->value, buffer + sizeof(key) + sizeof(size_t), value_len);
                    record->value[value_len] = '\0';
                    record->value_len = value_len;
                    record->sector = sector;
                
                    u32 hash = djb2_hash(key, strlen(key));
                    hash_add_rcu(kv_store, &record->hash_node, hash);
                    insert_rb_tree(record);
                    atomic_long_add(value_len, &total_disk_usage);
                    atomic_inc(&record_count);
                
                    hpkv_log(HPKV_LOG_INFO, "Added record for key: %s\n", key);
                } else {
                    hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for record value\n");
                    kmem_cache_free(record_cache, record);
                }
            } else {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for record\n");
            }
        } else if (key[0] == '\0') {
            // This is a deleted or empty record, skip it
            hpkv_log(HPKV_LOG_INFO, "Skipping deleted or empty record at sector %llu\n", (unsigned long long)sector);
        } else {
            hpkv_log(HPKV_LOG_WARNING, "Invalid record found at sector %llu. Key: %s, Value length: %zu\n", 
                   (unsigned long long)sector, key, value_len);
            corruption_detected = true;
            break;  // Stop processing further to avoid potential issues with corrupted data
        }

        brelse(bh);
        sector++;
    }

    vfree(buffer);

    // After loading all records from disk, process any pending write buffer entries
    struct write_buffer_entry *entry, *tmp;
    spin_lock(&write_buffer_lock);
    list_for_each_entry_safe(entry, tmp, &write_buffer, list) {
        // Update in-memory structures with the buffered record
        hash_add_rcu(kv_store, &entry->record->hash_node, djb2_hash(entry->record->key, strlen(entry->record->key)));
        insert_rb_tree(entry->record);
        atomic_long_add(entry->record->value_len, &total_disk_usage);
        atomic_inc(&record_count);

        // Remove from write buffer
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&write_buffer_lock);

    if (corruption_detected) {
        hpkv_log(HPKV_LOG_WARNING, "Corruption detected. Consider running a repair operation.\n");
        ret = -EUCLEAN;  // File system requires cleaning
    } else {
        hpkv_log(HPKV_LOG_INFO, "Finished loading indexes. Processed %llu sectors\n", (unsigned long long)sector);
        
        // Verify loaded data against metadata
        if (atomic_read(&record_count) != metadata.total_records ||
            atomic_long_read(&total_disk_usage) != metadata.total_size) {
            hpkv_log(HPKV_LOG_WARNING, "Mismatch between loaded data and metadata. "
                   "Loaded records: %d, Metadata records: %llu, "
                   "Loaded size: %ld, Metadata size: %llu\n",
                   atomic_read(&record_count), metadata.total_records,
                   atomic_long_read(&total_disk_usage), metadata.total_size);

            ret = update_metadata();
            if (ret < 0) {
                hpkv_log(HPKV_LOG_ERR, "Failed to update metadata after detected mismatch\n");
            }
            else{
                hpkv_log(HPKV_LOG_INFO, "Metadata updated successfully after detected mismatch\n");
            }
        }
    }

out:
    percpu_up_write(&rw_sem);
    return ret;
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
    struct hpkv_metadata metadata;
    int ret = 0;

    hpkv_log(HPKV_LOG_INFO, "Initializing empty device\n");

    bh = __getblk(bdev, HPKV_METADATA_BLOCK, BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to get block for initialization\n");
        return -EIO;
    }

    memset(&metadata, 0, sizeof(struct hpkv_metadata));
    memcpy(metadata.signature, HPKV_SIGNATURE, HPKV_SIGNATURE_SIZE);
    metadata.total_records = 0;
    metadata.total_size = 0;
    metadata.version = 1;  // Initial version

    memcpy(bh->b_data, &metadata, sizeof(struct hpkv_metadata));
    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    // Set the device size to one block (or more if needed)
    i_size_write(bdev->bd_inode, BLOCK_SIZE);

    return ret;
}

static bool is_zero_buffer(const void *buf, size_t size)
{
    const unsigned char *p = buf;
    size_t i;

    for (i = 0; i < size; i++) {
        if (p[i] != 0)
            return false;
    }

    return true;
}

static bool is_disk_empty(struct block_device *bdev)
{
    struct buffer_head *bh;
    int i;
    bool is_empty = true;

    // Check the first few blocks to see if they're all zeros
    for (i = 0; i < 10; i++) {
        bh = __bread(bdev, i, BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read block %d while checking if disk is empty\n", i);
            return false;  // Assume not empty if we can't read
        }

        if (!is_zero_buffer(bh->b_data, BLOCK_SIZE)) {
            is_empty = false;
            brelse(bh);
            break;
        }

        brelse(bh);
    }

    return is_empty;
}

static int __init hpkv_init(void)
{
    int ret;

    hpkv_log(HPKV_LOG_INFO, "Initializing module\n");
    hpkv_log(HPKV_LOG_INFO, "Mount path received: %s\n", mount_path);

    major_num = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_num < 0) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to register a major number\n");
        return major_num;
    }

    record_cache = kmem_cache_create("hpkv_record", sizeof(struct record), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!record_cache) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to create record cache\n");
        ret = -ENOMEM;
        goto error_unregister_chrdev;
    }
    hpkv_log(HPKV_LOG_INFO, "Record cache created successfully\n");

    hash_init(kv_store);
    hpkv_log(HPKV_LOG_INFO, "Hash table initialized\n");

    // Initialize rw_sem before opening the block device
    ret = percpu_init_rwsem(&rw_sem);
    if (ret) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to initialize percpu_rw_semaphore\n");
        goto error_destroy_cache;
    }

    hpkv_log(HPKV_LOG_INFO, "Attempting to open block device: %s\n", mount_path);
    bdev = blkdev_get_by_path(mount_path, FMODE_READ | FMODE_WRITE, THIS_MODULE);
    if (IS_ERR(bdev)) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to open block device, error %ld\n", PTR_ERR(bdev));
        ret = PTR_ERR(bdev);
        goto error_free_rwsem;
    }
    hpkv_log(HPKV_LOG_INFO, "Block device opened successfully\n");

    // Check if the device is valid and get its size
    if (!bdev->bd_disk) {
        hpkv_log(HPKV_LOG_ALERT, "Invalid block device\n");
        ret = -EINVAL;
        goto error_put_device;
    }

    // Initialize the write buffer
    INIT_LIST_HEAD(&write_buffer);
    spin_lock_init(&write_buffer_lock);
    init_waitqueue_head(&write_buffer_wait);

    // Start the write buffer thread
    write_buffer_thread = kthread_run(write_buffer_worker, NULL, "hpkv_write_buffer");
    if (IS_ERR(write_buffer_thread)) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to create write buffer thread\n");
        ret = PTR_ERR(write_buffer_thread);
        goto error_put_device;
    }

    ret = load_indexes();
    if (ret == -EINVAL) {
        if (initialize_if_empty) {
            if (is_disk_empty(bdev)) {
                hpkv_log(HPKV_LOG_INFO, "Device is empty. Initializing for HPKV use.\n");
                ret = initialize_empty_device();
                if (ret < 0) {
                    hpkv_log(HPKV_LOG_ERR, "Failed to initialize empty device\n");
                    goto error_put_device;
                }
            } else {
                hpkv_log(HPKV_LOG_ERR, "Device contains data but is not HPKV formatted. Refusing to initialize.\n");
                ret = -ENOTEMPTY;
                goto error_put_device;
            }
        } else {
            hpkv_log(HPKV_LOG_ERR, "Device is not formatted for HPKV use and initialize_if_empty is not set\n");
            ret = -ENODEV;
            goto error_put_device;
        }
    } else if (ret == -EUCLEAN) {
        hpkv_log(HPKV_LOG_WARNING, "Device requires cleaning or repair. Consider running a repair operation.\n");
        // For now, we'll continue loading but with a warning
        // TODO: Trigger a repair operation here
    } else if (ret < 0) {
        hpkv_log(HPKV_LOG_ERR, "Failed to load indexes\n");
        goto error_put_device;
    }

    hpkv_log(HPKV_LOG_INFO, "Creating proc entry\n");
    proc_create(PROC_ENTRY, 0, NULL, &hpkv_proc_fops);

    compact_wq = create_singlethread_workqueue("hpkv_compact");
    if (!compact_wq) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to create compaction workqueue\n");
        ret = -ENOMEM;
        goto error_remove_proc;
    }

    INIT_DELAYED_WORK(&compact_work, compact_work_handler);
    queue_delayed_work(compact_wq, &compact_work, COMPACT_INTERVAL);

    hpkv_log(HPKV_LOG_INFO, "Module loaded successfully\n");
    hpkv_log(HPKV_LOG_INFO, "Registered with major number %d\n", major_num);
    return 0;

error_remove_proc:
    remove_proc_entry(PROC_ENTRY, NULL);
error_put_device:
    blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
error_free_rwsem:
    percpu_free_rwsem(&rw_sem);
error_destroy_cache:
    kmem_cache_destroy(record_cache);
error_unregister_chrdev:
    unregister_chrdev(major_num, DEVICE_NAME);

    return ret;
}

static void __exit hpkv_exit(void)
{
    struct record *record;
    struct rb_node *node;
    int bkt;
    struct hlist_node *tmp;
    struct cached_record *cached;

    hpkv_log(HPKV_LOG_INFO, "Starting module unload\n");

    // Cancel and destroy the compaction work
    cancel_delayed_work_sync(&compact_work);
    destroy_workqueue(compact_wq);

    // Stop the write buffer thread and flush remaining entries
    if (write_buffer_thread) {
        kthread_stop(write_buffer_thread);
        write_buffer_thread = NULL;
    }
    flush_write_buffer();

    // Acquire write lock to prevent any concurrent access
    percpu_down_write(&rw_sem);

    // Clear the red-black tree and hash table
    while ((node = rb_first(&records_tree))) {
        record = rb_entry(node, struct record, tree_node);
        rb_erase(node, &records_tree);
        hash_del_rcu(&record->hash_node);
        
        // Free the record's value
        if (record->value) {
            kfree(record->value);
            record->value = NULL;
        }
        
        // Free the record structure directly instead of using RCU
        kmem_cache_free(record_cache, record);
    }

    // Clear cache
    spin_lock(&cache_lock);
    hash_for_each_safe(cache, bkt, tmp, cached, node) {
        hash_del(&cached->node);
        if (cached->value) {
            kfree(cached->value);
            cached->value = NULL;
        }
        kfree(cached);
    }
    cache_count = 0;
    spin_unlock(&cache_lock);

    percpu_up_write(&rw_sem);

    // Close the block device
    if (bdev) {
        blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
        bdev = NULL;
    }

    // Clean up other resources
    remove_proc_entry(PROC_ENTRY, NULL);
    
    // Ensure all RCU callbacks have completed before destroying the cache
    rcu_barrier();
    
    kmem_cache_destroy(record_cache);
    unregister_chrdev(major_num, DEVICE_NAME);
    percpu_free_rwsem(&rw_sem);

    hpkv_log(HPKV_LOG_INFO, "Module unloaded successfully\n");
}

module_init(hpkv_init);
module_exit(hpkv_exit);

