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
#include <linux/hashtable.h>
#include <linux/bitmap.h>
#include <linux/atomic.h>
#include <linux/smp.h>
#include <linux/types.h>

#define DEVICE_NAME "hpkv"
#define MAX_KEY_SIZE 512
#define MAX_VALUE_SIZE 102400  // 100 KB
#define HPKV_HASH_BITS (20) // 2^20 = 1,048,576 buckets
#define MAX_DISK_USAGE (1UL << 40) // 1 TB max disk usage
#define HPKV_BLOCK_SIZE 4096
#define PROC_ENTRY "hpkv_stats"
#define MEMORY_THRESHOLD_HIGH (totalram_pages() * PAGE_SIZE * 30 / 100)  // 30% of total RAM
#define MEMORY_THRESHOLD_LOW (totalram_pages() * PAGE_SIZE * 10 / 100)   // 10% of total RAM
#define CACHE_ADJUST_INTERVAL (5 * 60 * HZ)  // 5 minutes
#define COMPACT_INTERVAL (1800 * HZ) // Run compaction every 30 minutes
#define HPKV_SIGNATURE "HPKV_V2"
#define HPKV_SIGNATURE_SIZE 8
#define HPKV_METADATA_BLOCK 0
#define WRITE_BUFFER_SIZE 1024
#define WRITE_BUFFER_FLUSH_INTERVAL (HZ * 30) // 30 seconds
#define MAX_DEVICE_SIZE (1ULL << 40)  // 1 TB, adjust as needed
#define EXTENSION_SIZE (1024 * 1024)  // Extend by 1MB at a time
#define SECTORS_BITMAP_SIZE (MAX_DEVICE_SIZE / HPKV_BLOCK_SIZE)
#define WORK_TIMEOUT_MS 5000  // 5 seconds timeout for individual work items
#define HPKV_IOCTL_GET 0
#define HPKV_IOCTL_DELETE 1
#define HPKV_IOCTL_PARTIAL_UPDATE 5
#define HPKV_IOCTL_PURGE 3
#define HPKV_IOCTL_INSERT 4

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mehran Toosi");
MODULE_DESCRIPTION("High performance KV store kernel module, with advanced features");
MODULE_VERSION("1.2");

// Function prototypes
static u32 djb2_hash(const char *str, uint16_t len);
static struct record *search_record_in_memory(const char *key, uint16_t key_len);
static void insert_rb_tree(struct record *record);
static struct cached_record *cache_get(const char *key, uint16_t key_len);
static void cache_put(const char *key, uint16_t key_len, const char *value, size_t value_len, sector_t sector);
static int load_record_from_disk(sector_t sector, char **value, size_t *value_len);
static void record_free_rcu(struct rcu_head *head);
static struct record *record_find_rcu(const char *key, uint16_t key_len);
static int search_record(const char *key, uint16_t key_len, char **value, size_t *value_len);
static int write_buffer_size(void);
static sector_t find_free_sector(size_t required_size);
static int update_metadata(void);
static int update_metadata_size(loff_t new_size);
static int insert_or_update_record(const char *key, uint16_t key_len, const char *value, size_t value_len, bool is_partial_update);
static int delete_record(const char *key, uint16_t key_len);
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
static int extend_device(loff_t new_size);
static void flush_work_handler(struct work_struct *work);
static void write_record_work(struct work_struct *work);
static void metadata_update_work_func(struct work_struct *work);
static void release_sectors(sector_t start_sector, int num_sectors);
static int calculate_cache_size(void);
static void update_lru(struct cached_record *record);
static void evict_lru(void);
static void adjust_cache_size(void);
static void prefetch_adjacent(const char *key, uint16_t key_len);
static void cache_adjust_work_handler(struct work_struct *work);
static void mark_sectors_as_deleted(sector_t start_sector, int num_sectors);
static size_t calculate_record_size(uint16_t key_len, size_t value_len);

static int major_num;
static struct kmem_cache *record_cache;
static struct percpu_rw_semaphore rw_sem;
static atomic_t purge_in_progress = ATOMIC_INIT(0);
static atomic_t compact_in_progress = ATOMIC_INIT(0);
static atomic_t flush_running = ATOMIC_INIT(0);
static DECLARE_COMPLETION(flush_completion);

struct hpkv_metadata {
    char signature[HPKV_SIGNATURE_SIZE];
    uint64_t total_records;
    uint64_t total_size;
    uint64_t device_size;
    uint32_t version;
};

struct record {
    char *key;
    uint16_t key_len;
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
    char *key;
    uint16_t key_len;
    char *value;
    size_t value_len;
    sector_t sector;
    struct hlist_node node;
    struct list_head lru_list;
    unsigned long last_access;
};

enum operation_type {
    OP_INSERT,
    OP_UPDATE,
    OP_DELETE
};

struct write_buffer_entry {
    enum operation_type op;
    struct record *record;
    size_t old_value_len;
    struct list_head list;
    struct work_struct work;
    struct completion work_done;
    atomic_t work_status;  // 0: not started, 1: in progress, 2: completed, 3: failed
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
static atomic_t cache_count = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(cache_lock);
static LIST_HEAD(lru_list);
static int cache_size_percentage = 10;  // Cache size as a percentage of total records

static DECLARE_BITMAP(allocated_sectors, SECTORS_BITMAP_SIZE);
static DEFINE_SPINLOCK(sector_allocation_lock);

static struct block_device *bdev;
static struct bdev_handle *bdev_handle;

static char *mount_path = "/dev/sdb";
module_param(mount_path, charp, 0644);
MODULE_PARM_DESC(mount_path, "Path to the block device for persistent storage");

static bool initialize_if_empty = true;
module_param(initialize_if_empty, bool, 0644);
MODULE_PARM_DESC(initialize_if_empty, "Initialize the device if it's empty (default: true)");

static bool force_initialize = false;
module_param(force_initialize, bool, 0644);
MODULE_PARM_DESC(force_initialize, "Force initialize the device even if it contains data (default: false)");

static bool force_read_disk = false;
module_param(force_read_disk, bool, 0644);
MODULE_PARM_DESC(force_read_disk, "Force reading the entire disk even beyond metadata size (default: false)");

static struct workqueue_struct *compact_wq;
static struct delayed_work compact_work;

static struct workqueue_struct *flush_wq;
static struct work_struct hpkv_flush_work;
static DECLARE_WORK(metadata_update_work, metadata_update_work_func);
static DECLARE_DELAYED_WORK(cache_adjust_work, cache_adjust_work_handler);


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
            if (log_level == HPKV_LOG_DEBUG) { \
                printk("%sHPKV: %s:%d: " fmt, kern_level, __func__, __LINE__, ##__VA_ARGS__); \
            } else { \
                printk("%sHPKV: " fmt, kern_level, ##__VA_ARGS__); \
            } \
        } \
    } while (0)

static u32 djb2_hash(const char *str, uint16_t len)
{
    u32 hash = 5381;
    uint16_t i;

    for (i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + str[i];

    return hash;
}

static struct record *search_record_in_memory(const char *key, uint16_t key_len)
{
    struct rb_node *node;
    struct record *data;
    int result;

    rcu_read_lock();
    node = records_tree.rb_node;

    while (node) {
        data = container_of(node, struct record, tree_node);
        result = memcmp(key, data->key, min(key_len, data->key_len));
        if (result == 0)
            result = (int)key_len - (int)data->key_len;

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else {
            rcu_read_unlock();
            return data;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static void insert_rb_tree(struct record *record)
{
    struct rb_node **new = &(records_tree.rb_node), *parent = NULL;

    while (*new) {
        struct record *this = container_of(*new, struct record, tree_node);
        int result = memcmp(record->key, this->key, min(record->key_len, this->key_len));
        if (result == 0)
            result = (int)record->key_len - (int)this->key_len;

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

static struct cached_record *cache_get(const char *key, uint16_t key_len)
{
    struct cached_record *cached;
    u32 hash = djb2_hash(key, key_len);

    rcu_read_lock();
    hash_for_each_possible(cache, cached, node, hash) {
        if (cached->key_len == key_len && memcmp(cached->key, key, key_len) == 0) {
            rcu_read_unlock();
            return cached;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static int calculate_cache_size(void)
{
    int total_records = atomic_read(&record_count);
    int cache_size = max(1000, (total_records * cache_size_percentage) / 100);
    hpkv_log(HPKV_LOG_DEBUG, "Calculated cache size: %d (total records: %d, percentage: %d%%)\n", 
             cache_size, total_records, cache_size_percentage);
    return cache_size;
}

static void update_lru(struct cached_record *record)
{
    if (!record) {
        hpkv_log(HPKV_LOG_ERR, "Attempted to update LRU for null record\n");
        return;
    }

    if (list_empty(&record->lru_list)) {
        hpkv_log(HPKV_LOG_WARNING, "Record not in LRU list, adding it\n");
        list_add(&record->lru_list, &lru_list);
    } else {
        list_del(&record->lru_list);
        list_add(&record->lru_list, &lru_list);
    }
    record->last_access = jiffies;
    hpkv_log(HPKV_LOG_DEBUG, "Updated LRU for key: %.*s, new access time: %lu\n", 
             record->key_len, record->key, record->last_access);
}

static void evict_lru(void)
{
    struct cached_record *victim;
    victim = list_last_entry(&lru_list, struct cached_record, lru_list);
    hash_del(&victim->node);
    list_del(&victim->lru_list);
    hpkv_log(HPKV_LOG_DEBUG, "Evicted LRU entry for key: %.*s, last access time: %lu\n", 
             victim->key_len, victim->key, victim->last_access);
    kfree(victim->key);
    kfree(victim->value);
    kfree(victim);
    atomic_dec(&cache_count);
}

static void adjust_cache_size(void)
{
    unsigned long available_memory = si_mem_available() * PAGE_SIZE;
    int current_cache_size = calculate_cache_size();
    int old_percentage = cache_size_percentage;
    int current_count = atomic_read(&cache_count);
    
    if (available_memory > MEMORY_THRESHOLD_HIGH && current_count * 10 < current_cache_size * 12) {
        // Increase cache size
        cache_size_percentage = min(cache_size_percentage + 5, 30);
    } else if (available_memory < MEMORY_THRESHOLD_LOW || current_count * 10 > current_cache_size * 9) {
        // Decrease cache size
        cache_size_percentage = max(cache_size_percentage - 5, 5);
    }

    if (old_percentage != cache_size_percentage) {
        hpkv_log(HPKV_LOG_INFO, "Adjusted cache size percentage from %d%% to %d%%. Current count: %d, Target size: %d, Available memory: %lu bytes\n", 
                 old_percentage, cache_size_percentage, current_count, current_cache_size, available_memory);
    }
}

static void prefetch_adjacent(const char *key, uint16_t key_len)
{
    struct record *record;
    struct rb_node *node;
    
    if (!key || key_len == 0) {
        hpkv_log(HPKV_LOG_ERR, "Invalid input to prefetch_adjacent\n");
        return;
    }

    rcu_read_lock();
    record = search_record_in_memory(key, key_len);
    if (record) {
        node = rb_next(&record->tree_node);
        if (node) {
            record = rb_entry(node, struct record, tree_node);

            if(atomic_read(&record->refcount) == 0) {
                // No references to this record, so it's scheduled for deletion
                rcu_read_unlock();
                return;
            }

            if (record->value == NULL && record->value_len > 0) {
                // Load the value from disk
                char *value = NULL;
                size_t loaded_value_len = 0;
                if (load_record_from_disk(record->sector, &value, &loaded_value_len) == 0) {
                    if (value && loaded_value_len > 0) {
                        cache_put(record->key, record->key_len, value, loaded_value_len, record->sector);
                        hpkv_log(HPKV_LOG_DEBUG, "Prefetched adjacent key: %.*s (length: %u)\n", 
                            record->key_len, record->key, record->key_len);
                    }
                    kfree(value);  // Free the loaded value
                }
            }
            else if (record->value != NULL && record->value_len > 0) {
                cache_put(record->key, record->key_len, record->value, record->value_len, record->sector);
                hpkv_log(HPKV_LOG_DEBUG, "Prefetched adjacent key: %.*s (length: %u)\n", 
                         record->key_len, record->key, record->key_len);
            }
        } else {
            hpkv_log(HPKV_LOG_DEBUG, "No adjacent key found for prefetching after key: %.*s\n", 
                     key_len, key);
        }
    } else {
        hpkv_log(HPKV_LOG_DEBUG, "Unable to prefetch: key not found in memory: %.*s\n", 
                 key_len, key);
    }
    rcu_read_unlock();
}

static void cache_put(const char *key, uint16_t key_len, const char *value, size_t value_len, sector_t sector)
{
    struct cached_record *cached;
    u32 hash;

    if (!key || !value || key_len == 0 || value_len == 0) {
        hpkv_log(HPKV_LOG_ERR, "Invalid input to cache_put\n");
        return;
    }

    hash = djb2_hash(key, key_len);

    spin_lock(&cache_lock);

    cached = cache_get(key, key_len);
    if (cached) {
        // Update existing entry
        char *new_value = kmalloc(value_len, GFP_ATOMIC);
        if (new_value) {
            memcpy(new_value, value, value_len);
            if (cached->value) {
                kfree(cached->value);
            }
            cached->value = new_value;
            cached->value_len = value_len;
            cached->sector = sector;
            update_lru(cached);
            hpkv_log(HPKV_LOG_DEBUG, "Updated existing cache entry for key: %.*s\n", key_len, key);
        } else {
            hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for updated cache value\n");
        }
    } else {
        // Add new entry
        if (atomic_read(&cache_count) >= calculate_cache_size()) {
            evict_lru();
        }
        cached = kmalloc(sizeof(*cached), GFP_ATOMIC);
        if (cached) {
            cached->key = kmalloc(key_len, GFP_ATOMIC);
            cached->value = kmalloc(value_len, GFP_ATOMIC);
            if (cached->key && cached->value) {
                memcpy(cached->key, key, key_len);
                cached->key_len = key_len;
                memcpy(cached->value, value, value_len);
                cached->value_len = value_len;
                cached->sector = sector;
                hash_add(cache, &cached->node, hash);
                INIT_LIST_HEAD(&cached->lru_list);
                list_add(&cached->lru_list, &lru_list);
                atomic_inc(&cache_count);
                hpkv_log(HPKV_LOG_DEBUG, "Added new cache entry for key: %.*s\n", key_len, key);
            } else {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for new cache entry\n");
                if (cached->key) kfree(cached->key);
                if (cached->value) kfree(cached->value);
                kfree(cached);
            }
        } else {
            hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for new cache record\n");
        }
    }

    spin_unlock(&cache_lock);
}

static void cache_adjust_work_handler(struct work_struct *work)
{
    hpkv_log(HPKV_LOG_DEBUG, "Starting cache size adjustment\n");
    adjust_cache_size();
    queue_delayed_work(system_wq, &cache_adjust_work, CACHE_ADJUST_INTERVAL);
    hpkv_log(HPKV_LOG_DEBUG, "Finished cache size adjustment, next adjustment scheduled\n");
}

static size_t calculate_record_size(uint16_t key_len, size_t value_len)
{
    return sizeof(uint16_t) + key_len + sizeof(size_t) + value_len;
}

static int load_record_from_disk(sector_t sector, char **value, size_t *value_len)
{
    struct buffer_head *bh;
    uint16_t key_len;
    size_t buffer_size;
    int i;
    char *buffer;

    bh = __bread(bdev, sector, HPKV_BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to read sector %llu\n", (unsigned long long)sector);
        return -EIO;
    }

    // Read the key length
    memcpy(&key_len, bh->b_data, sizeof(uint16_t));

    // Read the value length
    memcpy(value_len, bh->b_data + sizeof(uint16_t) + key_len, sizeof(size_t));

    // Calculate total length and number of sectors to read
    size_t total_record_size = calculate_record_size(key_len, *value_len);
    int sectors_to_read = DIV_ROUND_UP(total_record_size, HPKV_BLOCK_SIZE);

    // Calculate buffer size
    buffer_size = sectors_to_read * HPKV_BLOCK_SIZE;

    hpkv_log(HPKV_LOG_DEBUG, "Loading record: key_len=%u, value_len=%zu, total_len=%zu, sectors_to_read=%d, buffer_size=%zu\n",
             key_len, *value_len, total_record_size, sectors_to_read, buffer_size);

    // Sanity check to prevent excessive memory allocation
    if (*value_len > MAX_VALUE_SIZE || key_len > MAX_KEY_SIZE) {
        hpkv_log(HPKV_LOG_ERR, "Record size exceeds maximum allowed size: key_len=%u, value_len=%zu\n", key_len, *value_len);
        brelse(bh);
        return -EINVAL;
    }

    buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer for reading record\n");
        brelse(bh);
        return -ENOMEM;
    }

    // Copy the first sector
    memcpy(buffer, bh->b_data, HPKV_BLOCK_SIZE);
    brelse(bh);

    // Read remaining sectors if necessary
    for (i = 1; i < sectors_to_read; i++) {
        bh = __bread(bdev, sector + i, HPKV_BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read sector %llu\n", (unsigned long long)(sector + i));
            kfree(buffer);
            return -EIO;
        }
        memcpy(buffer + i * HPKV_BLOCK_SIZE, bh->b_data, HPKV_BLOCK_SIZE);
        brelse(bh);
    }

    *value = kmalloc(*value_len, GFP_KERNEL);
    if (!*value) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for value\n");
        kfree(buffer);
        return -ENOMEM;
    }

    // Copy the value from the buffer
    memcpy(*value, buffer + sizeof(uint16_t) + key_len + sizeof(size_t), *value_len);

    hpkv_log(HPKV_LOG_DEBUG, "Successfully loaded record: value_len=%zu\n", *value_len);

    kfree(buffer);
    return 0;
}

static void record_free_rcu(struct rcu_head *head)
{
    struct record *record;
    char *key_to_free = NULL;
    char *value_to_free = NULL;

    if (!head) {
        hpkv_log(HPKV_LOG_ERR, "Null RCU head passed to record_free_rcu\n");
        return;
    }

    record = container_of(head, struct record, rcu);
    if (!record) {
        hpkv_log(HPKV_LOG_ERR, "Failed to obtain record from RCU head in record_free_rcu\n");
        return;
    }

    rcu_read_lock();
    key_to_free = rcu_dereference(record->key);
    value_to_free = rcu_dereference(record->value);
    rcu_read_unlock();

    // Free the key and value outside the RCU read-side critical section
    if (key_to_free) {
        kfree(key_to_free);
    }
    if (value_to_free) {
        kfree(value_to_free);
    }

    // Use a memory barrier before freeing the record
    smp_wmb();

    // Free the record
    kmem_cache_free(record_cache, record);
    hpkv_log(HPKV_LOG_DEBUG, "Record freed in RCU callback\n");
}

static struct record *record_find_rcu(const char *key, uint16_t key_len)
{
    struct record *record;
    u32 hash = djb2_hash(key, key_len);

    rcu_read_lock();
    hash_for_each_possible_rcu(kv_store, record, hash_node, hash) {
        if (record->key_len == key_len && memcmp(record->key, key, key_len) == 0) {
            rcu_read_unlock();
            return record;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static int search_record(const char *key, uint16_t key_len, char **value, size_t *value_len)
{
    struct record *record;
    struct cached_record *cached;
    int ret = -ENOENT;

    if (!key || !value || !value_len) {
        hpkv_log(HPKV_LOG_ERR, "Invalid parameters passed to search_record\n");
        return -EINVAL;
    }

    hpkv_log(HPKV_LOG_DEBUG, "Searching for key: %.*s (length: %u)\n", key_len, key, key_len);

    // First, check the cache
    cached = cache_get(key, key_len);
    if (cached) {
        *value = kmalloc(cached->value_len, GFP_KERNEL);
        if (!*value) {
            hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for value\n");
            return -ENOMEM;
        }
        memcpy(*value, cached->value, cached->value_len);
        *value_len = cached->value_len;
        hpkv_log(HPKV_LOG_DEBUG, "Found key %.*s in cache\n", key_len, key);
        update_lru(cached);
        prefetch_adjacent(key, key_len);
        return 0;
    }

    // If not in cache, search in-memory structures
    rcu_read_lock();
    record = record_find_rcu(key, key_len);
    if (record) {
        if(atomic_read(&record->refcount) == 0) {
            // No references to this record, so it's scheduled for deletion
            rcu_read_unlock();
            return -ENOENT;
        }

        smp_rmb();  // Ensure we see the latest value of record->value
        if (record->value) {
            *value = kmalloc(record->value_len, GFP_KERNEL);
            if (!*value) {
                rcu_read_unlock();
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for value\n");
                return -ENOMEM;
            }
            memcpy(*value, record->value, record->value_len);
            *value_len = record->value_len;
            ret = 0;
            hpkv_log(HPKV_LOG_DEBUG, "Found key %.*s in memory\n", key_len, key);
        } else {
            // Value is on disk, need to read it
            ret = load_record_from_disk(record->sector, value, value_len);
            if (ret == 0) {
                // Update cache with the loaded value
                cache_put(key, key_len, *value, *value_len, record->sector);
                hpkv_log(HPKV_LOG_DEBUG, "Found key %.*s on disk and updated cache\n", key_len, key);
            } else {
                hpkv_log(HPKV_LOG_ERR, "Failed to load record from disk for key %.*s\n", key_len, key);
            }
        }
    }
    else {
        hpkv_log(HPKV_LOG_DEBUG, "Key %.*s not found in memory or cache\n", key_len, key);
        ret = -ENOENT;
    }
    rcu_read_unlock();

    if (ret == 0) {
        prefetch_adjacent(key, key_len);
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

static sector_t find_free_sector(size_t required_size)
{
    sector_t sector = 1;  // Start from sector 1 (sector 0 is reserved for metadata)
    struct buffer_head *bh;
    char *buffer;
    loff_t device_size;
    sector_t first_free_sector = 0;
    sector_t first_deleted_sector = 0;
    int required_sectors = DIV_ROUND_UP(required_size, HPKV_BLOCK_SIZE);
    int contiguous_free_sectors = 0;
    int contiguous_deleted_sectors = 0;
    sector_t device_sectors = i_size_read(bdev->bd_inode) / HPKV_BLOCK_SIZE;
    sector_t found_sector = 0;

    spin_lock(&sector_allocation_lock);

    // First, try to find contiguous free sectors in the bitmap
    while (sector + required_sectors <= device_sectors) {
        if (!test_bit(sector, allocated_sectors)) {
            bool is_range_free = true;
            for (int i = 0; i < required_sectors; i++) {
                if (test_bit(sector + i, allocated_sectors)) {
                    is_range_free = false;
                    break;
                }
            }
            if (is_range_free) {
                found_sector = sector;
                // Mark the sectors as allocated
                for (int i = 0; i < required_sectors; i++) {
                    set_bit(sector + i, allocated_sectors);
                }
                smp_mb();  // Memory barrier after bit operations
                break;
            }
        }
        sector++;
    }

    spin_unlock(&sector_allocation_lock);

    if (found_sector != 0) {
        hpkv_log(HPKV_LOG_INFO, "Found free sector at %llu using bitmap for size %zu (requires %d sectors)\n", 
                 (unsigned long long)found_sector, required_size, required_sectors);
        return found_sector;
    }

    // If not found in bitmap, fallback to the disk scan
    hpkv_log(HPKV_LOG_INFO, "Falling back to device scan for finding free sector\n");

    device_size = i_size_read(bdev->bd_inode);

    buffer = kmalloc(HPKV_BLOCK_SIZE, GFP_KERNEL);
    if (!buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for find_free_sector\n");
        return -ENOMEM;
    }

    sector = 1;  // Reset sector to 1
    while (sector * HPKV_BLOCK_SIZE < device_size) {
        bh = __bread(bdev, sector, HPKV_BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read sector %llu\n", (unsigned long long)sector);
            sector++;
            continue;
        }

        memcpy(buffer, bh->b_data, HPKV_BLOCK_SIZE);
        brelse(bh);

        if (memcmp(buffer, "\0DELETED", 8) == 0) {
            if (first_deleted_sector == 0) {
                first_deleted_sector = sector;
            }
            contiguous_deleted_sectors++;
            if (contiguous_deleted_sectors >= required_sectors) {
                spin_lock(&sector_allocation_lock);
                for (int i = 0; i < required_sectors; i++) {
                    set_bit(first_deleted_sector + i, allocated_sectors);
                }
                smp_mb();  // Memory barrier after bit operations
                spin_unlock(&sector_allocation_lock);
                kfree(buffer);
                hpkv_log(HPKV_LOG_INFO, "Found contiguous deleted sectors at %llu\n", 
                         (unsigned long long)first_deleted_sector);
                return first_deleted_sector;
            }
        } else {
            contiguous_deleted_sectors = 0;
        }

        if (buffer[0] == '\0') {
            if (first_free_sector == 0) {
                first_free_sector = sector;
            }
            contiguous_free_sectors++;
            if (contiguous_free_sectors >= required_sectors) {
                spin_lock(&sector_allocation_lock);
                for (int i = 0; i < required_sectors; i++) {
                    set_bit(first_free_sector + i, allocated_sectors);
                }
                smp_mb();  // Memory barrier after bit operations
                spin_unlock(&sector_allocation_lock);
                kfree(buffer);
                hpkv_log(HPKV_LOG_INFO, "Found contiguous free sectors at %llu\n", 
                         (unsigned long long)first_free_sector);
                return first_free_sector;
            }
        } else {
            contiguous_free_sectors = 0;
        }

        sector++;
    }

    kfree(buffer);

    hpkv_log(HPKV_LOG_INFO, "No suitable free space found. Recommending extension.\n");
    return -ENOSPC;
}

static void release_sectors(sector_t start_sector, int num_sectors)
{
    spin_lock(&sector_allocation_lock);
    for (int i = 0; i < num_sectors; i++) {
        clear_bit(start_sector + i, allocated_sectors);
    }
    smp_mb();  // Memory barrier after bit operations
    spin_unlock(&sector_allocation_lock);

    hpkv_log(HPKV_LOG_INFO, "Released %d sectors starting at %llu\n", 
             num_sectors, (unsigned long long)start_sector);
}

static int update_metadata(void)
{
    struct buffer_head *bh;
    struct hpkv_metadata metadata;

    bh = __bread(bdev, HPKV_METADATA_BLOCK, HPKV_BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to read metadata block for update\n");
        return -EIO;
    }

    memcpy(&metadata, bh->b_data, sizeof(struct hpkv_metadata));

    // Update the fields
    metadata.total_records = atomic_read(&record_count);
    metadata.total_size = atomic_long_read(&total_disk_usage);
    metadata.device_size = i_size_read(bdev->bd_inode);  // Update the actual device size

    // Write back the updated metadata
    lock_buffer(bh);
    memcpy(bh->b_data, &metadata, sizeof(struct hpkv_metadata));
    set_buffer_uptodate(bh);
    mark_buffer_dirty(bh);
    unlock_buffer(bh);

    int ret = sync_dirty_buffer(bh);
    if (ret) {
        hpkv_log(HPKV_LOG_ERR, "Failed to sync updated metadata\n");
    } else {
        hpkv_log(HPKV_LOG_INFO, "Updated metadata - Total records: %llu, Total size: %llu bytes, Device size: %llu bytes, Version: %u\n",
               metadata.total_records, metadata.total_size, metadata.device_size, metadata.version);
    }

    brelse(bh);

    return ret;
}

static int update_metadata_size(loff_t new_size)
{
    struct buffer_head *bh;
    struct hpkv_metadata metadata;

    bh = __bread(bdev, HPKV_METADATA_BLOCK, HPKV_BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to read metadata block for update\n");
        return -EIO;
    }

    memcpy(&metadata, bh->b_data, sizeof(struct hpkv_metadata));

    // Update the total_size field
    metadata.total_size = new_size;

    // Write back the updated metadata
    lock_buffer(bh);
    memcpy(bh->b_data, &metadata, sizeof(struct hpkv_metadata));
    set_buffer_uptodate(bh);
    mark_buffer_dirty(bh);
    unlock_buffer(bh);

    int ret = sync_dirty_buffer(bh);
    if (ret) {
        hpkv_log(HPKV_LOG_ERR, "Failed to sync updated metadata size\n");
    } else {
        hpkv_log(HPKV_LOG_INFO, "Updated metadata size - New total size: %llu bytes\n", new_size);
    }

    brelse(bh);

    return ret;
}

static int insert_or_update_record(const char *key, uint16_t key_len, const char *value, size_t value_len, bool is_partial_update)
{
    struct record *new_record, *old_record;
    struct write_buffer_entry *wb_entry, *wb_delete_entry;
    int ret = 0;
    u32 hash;

    if (!key || !value || value_len == 0 || value_len > MAX_VALUE_SIZE) {
        hpkv_log(HPKV_LOG_ERR, "Invalid parameters for insert_or_update_record\n");
        return -EINVAL;
    }

    if (!record_cache) {
        hpkv_log(HPKV_LOG_ERR, "record_cache is not initialized\n");
        return -EINVAL;
    }

    hash = djb2_hash(key, key_len);

    // Allocate memory for new_record using GFP_KERNEL flag
    new_record = kmem_cache_zalloc(record_cache, GFP_KERNEL);
    if (!new_record) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for new record\n");
        return -ENOMEM;
    }

    // Initialize the new_record structure
    new_record->key = kmalloc(key_len, GFP_KERNEL);
    if (!new_record->key) {
        kmem_cache_free(record_cache, new_record);
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for key\n");
        return -ENOMEM;
    }
    memcpy(new_record->key, key, key_len);
    new_record->key_len = key_len;

    // Update in-memory data structures
    percpu_down_write(&rw_sem);

    old_record = record_find_rcu(key, key_len);
    if (old_record) {
        hpkv_log(HPKV_LOG_INFO, "Updating existing record for key: %.*s\n", key_len, key);
        
        // Set refcount to 1 for the new record
        atomic_set(&new_record->refcount, 1);
        
        if (is_partial_update) {
            // Load the existing value if it's not in memory
            char *old_value = NULL;
            size_t old_value_len = 0;
            if (!old_record->value) {
                ret = load_record_from_disk(old_record->sector, &old_value, &old_value_len);
                if (ret < 0) {
                    percpu_up_write(&rw_sem);
                    kmem_cache_free(record_cache, new_record);
                    hpkv_log(HPKV_LOG_ERR, "Failed to load existing record for partial update\n");
                    return ret;
                }
            } else {
                old_value = old_record->value;
                old_value_len = old_record->value_len;
            }

            // Perform partial update
            size_t new_len = old_value_len + value_len;
            if (new_len > MAX_VALUE_SIZE) {
                percpu_up_write(&rw_sem);
                if (old_value != old_record->value) {
                    kfree(old_value);
                }
                kmem_cache_free(record_cache, new_record);
                hpkv_log(HPKV_LOG_ERR, "Partial update exceeds maximum value size\n");
                return -EMSGSIZE;
            }
            new_record->value = kmalloc(new_len, GFP_KERNEL);
            if (!new_record->value) {
                percpu_up_write(&rw_sem);
                if (old_value != old_record->value) {
                    kfree(old_value);
                }
                kmem_cache_free(record_cache, new_record);
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for partial update\n");
                return -ENOMEM;
            }
            memcpy(new_record->value, old_value, old_value_len);
            memcpy(new_record->value + old_value_len, value, value_len);
            new_record->value_len = new_len;

            if (old_value != old_record->value) {
                kfree(old_value);
            }
        } else {
            // Perform regular update
            new_record->value = kmalloc(value_len, GFP_KERNEL);
            if (!new_record->value) {
                percpu_up_write(&rw_sem);
                kmem_cache_free(record_cache, new_record);
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for regular update\n");
                return -ENOMEM;
            }
            memcpy(new_record->value, value, value_len);
            new_record->value_len = value_len;
        }

        // Remove old record from in-memory structures
        hash_del_rcu(&old_record->hash_node);
        rb_erase(&old_record->tree_node, &records_tree);
        atomic_set(&old_record->refcount, 0);
        smp_wmb();
        atomic_long_sub(old_record->value_len, &total_disk_usage);
    } else {
        hpkv_log(HPKV_LOG_INFO, "Inserting new record for key: %.*s\n", key_len, key);
        // Set refcount to 1 for the new record
        atomic_set(&new_record->refcount, 1);
        new_record->value = kmalloc(value_len, GFP_KERNEL);
        if (!new_record->value) {
            percpu_up_write(&rw_sem);
            kmem_cache_free(record_cache, new_record);
            hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for new insert\n");
            return -ENOMEM;
        }
        memcpy(new_record->value, value, value_len);
        new_record->value_len = value_len;
        atomic_inc(&record_count);
    }

    // Insert new record
    hash_add_rcu(kv_store, &new_record->hash_node, hash);
    insert_rb_tree(new_record);
    smp_wmb();  // Ensure all previous writes are visible before updating counters
    atomic_long_add(new_record->value_len, &total_disk_usage);

    percpu_up_write(&rw_sem);

    // Add new record to write buffer
    wb_entry = kmalloc(sizeof(*wb_entry), GFP_KERNEL);
    if (!wb_entry) {
        // Rollback changes if we can't add to write buffer
        percpu_down_write(&rw_sem);
        hash_del_rcu(&new_record->hash_node);
        rb_erase(&new_record->tree_node, &records_tree);
        atomic_long_sub(new_record->value_len, &total_disk_usage);
        if (old_record) {
            // Restore old record
            hash_add_rcu(kv_store, &old_record->hash_node, hash);
            insert_rb_tree(old_record);
            atomic_set(&old_record->refcount, 1);
            smp_wmb();
            atomic_long_add(old_record->value_len, &total_disk_usage);
        } else {
            atomic_dec(&record_count);
        }
        percpu_up_write(&rw_sem);

        kfree(new_record->value);
        kmem_cache_free(record_cache, new_record);
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for write buffer entry\n");
        return -ENOMEM;
    }

    wb_entry->op = old_record ? OP_UPDATE : OP_INSERT;
    wb_entry->record = new_record;
    wb_entry->old_value_len = old_record ? old_record->value_len : 0;
    INIT_WORK(&wb_entry->work, write_record_work);

    spin_lock(&write_buffer_lock);
    list_add_tail(&wb_entry->list, &write_buffer);

    // If there was an old record, add a separate delete entry to the write buffer
    if (old_record) {
        wb_delete_entry = kmalloc(sizeof(*wb_delete_entry), GFP_KERNEL);
        if (wb_delete_entry) {
            wb_delete_entry->op = OP_DELETE;
            wb_delete_entry->record = old_record;
            wb_delete_entry->old_value_len = old_record->value_len;
            INIT_WORK(&wb_delete_entry->work, write_record_work);
            list_add_tail(&wb_delete_entry->list, &write_buffer);
        } else {
            hpkv_log(HPKV_LOG_WARNING, "Failed to allocate memory for delete write buffer entry\n");
        }
    }

    spin_unlock(&write_buffer_lock);
    
    wake_up(&write_buffer_wait);

    hpkv_log(HPKV_LOG_INFO, "Successfully queued %s operation for key: %.*s\n", 
             old_record ? (is_partial_update ? "partial update" : "update") : "insert", key_len, key);
    return ret;
}

static int delete_record(const char *key, uint16_t key_len)
{
    struct record *record;
    struct write_buffer_entry *wb_entry;
    int ret = 0;

    percpu_down_write(&rw_sem);

    record = record_find_rcu(key, key_len);
    if (!record) {
        percpu_up_write(&rw_sem);
        return -ENOENT;
    }

    hash_del_rcu(&record->hash_node);
    rb_erase(&record->tree_node, &records_tree);
    atomic_long_sub(record->value_len, &total_disk_usage);
    atomic_dec(&record_count);

    // Set refcount to 0 to indicate deletion
    atomic_set(&record->refcount, 0);

    percpu_up_write(&rw_sem);

    // Add delete operation to write buffer
    wb_entry = kmalloc(sizeof(*wb_entry), GFP_KERNEL);
    if (!wb_entry) {
        // Rollback changes if we can't add to write buffer
        percpu_down_write(&rw_sem);
        hash_add_rcu(kv_store, &record->hash_node, djb2_hash(record->key, record->key_len));
        insert_rb_tree(record);
        atomic_long_add(record->value_len, &total_disk_usage);
        atomic_inc(&record_count);
        atomic_set(&record->refcount, 1);
        percpu_up_write(&rw_sem);
        return -ENOMEM;
    }

    wb_entry->op = OP_DELETE;
    wb_entry->record = record;
    wb_entry->old_value_len = record->value_len;
    INIT_WORK(&wb_entry->work, write_record_work);

    spin_lock(&write_buffer_lock);
    list_add_tail(&wb_entry->list, &write_buffer);
    spin_unlock(&write_buffer_lock);

    wake_up(&write_buffer_wait);

    // Remove from cache
    spin_lock(&cache_lock);
    struct cached_record *cached;
    hash_for_each_possible(cache, cached, node, djb2_hash(key, key_len)) {
        if (cached->key_len == key_len && memcmp(cached->key, key, key_len) == 0) {
            hash_del(&cached->node);
            list_del(&cached->lru_list);
            kfree(cached->key);
            kfree(cached->value);
            kfree(cached);
            atomic_dec(&cache_count);
            break;
        }
    }
    spin_unlock(&cache_lock);

    // Release sectors and free the record in write_record_work

    hpkv_log(HPKV_LOG_INFO, "Successfully queued delete operation for key: %.*s\n", key_len, key);
    return ret;
}

static int extend_device(loff_t new_size)
{
    int ret = 0;
    struct bdev_handle *bdev_ro_handle = NULL;
    struct block_device *bdev_ro = NULL;
    loff_t current_size = i_size_read(bdev->bd_inode);
    unsigned long new_sectors;

    hpkv_log(HPKV_LOG_INFO, "Current device size: %lld bytes, Requested size: %lld bytes\n", current_size, new_size);

    // Check if extension is actually needed
    if (new_size <= current_size) {
        hpkv_log(HPKV_LOG_INFO, "Device size is already sufficient. No extension needed.\n");
        return 0;
    }

    // Cap the new size to MAX_DEVICE_SIZE
    if (new_size > MAX_DEVICE_SIZE) {
        new_size = MAX_DEVICE_SIZE;
        hpkv_log(HPKV_LOG_WARNING, "Requested size exceeds maximum. Capping at %llu bytes\n", MAX_DEVICE_SIZE);
    }

    // Extend by smaller increments
    new_size = min(new_size, current_size + EXTENSION_SIZE);

    hpkv_log(HPKV_LOG_INFO, "Attempting to extend device to %lld bytes\n", new_size);

    // Reopen the block device in read-only mode
    bdev_ro_handle = bdev_open_by_path(mount_path, FMODE_READ, NULL, NULL);
    if (IS_ERR(bdev_ro_handle)) {
        hpkv_log(HPKV_LOG_ERR, "Failed to reopen block device in read-only mode\n");
        return PTR_ERR(bdev_ro_handle);
    }
    bdev_ro = bdev_ro_handle->bdev;

    // Calculate the new number of sectors
    new_sectors = new_size / bdev_ro->bd_disk->queue->limits.logical_block_size;

    // Set the new capacity
    set_capacity(bdev_ro->bd_disk, new_sectors);
    hpkv_log(HPKV_LOG_INFO, "Set new capacity to %lu sectors\n", new_sectors);

    // Update the size in our main bdev structure
    i_size_write(bdev->bd_inode, new_size);
    hpkv_log(HPKV_LOG_INFO, "Updated inode size to %lld bytes\n", new_size);

    // Update the bitmap to reflect the new size
    spin_lock(&sector_allocation_lock);
    bitmap_clear(allocated_sectors, current_size / HPKV_BLOCK_SIZE, (new_size - current_size) / HPKV_BLOCK_SIZE);
    smp_mb();  // Memory barrier after bit operations
    spin_unlock(&sector_allocation_lock);

    // Update metadata with new size
    ret = update_metadata_size(new_size);
    if (ret) {
        hpkv_log(HPKV_LOG_ERR, "Failed to update metadata with new size\n");
    } else {
        hpkv_log(HPKV_LOG_INFO, "Successfully updated metadata with new size\n");
    }

    // Close the read-only block device
    bdev_release(bdev_ro_handle);

    return ret;
}

static void write_record_to_disk(struct record *record)
{
    struct buffer_head *bh;
    loff_t device_size, new_size;
    int required_sectors, ret, i;
    char *write_buffer;

    if (!record) {
        hpkv_log(HPKV_LOG_ERR, "Attempted to write null record to disk\n");
        return;
    }

    smp_rmb();  // Memory barrier before reading record data
    if (!record->value || record->value_len == 0) {
        hpkv_log(HPKV_LOG_ERR, "Attempted to write invalid record to disk. Key: %.*s, Value length: %zu\n", 
                 record->key_len, record->key, record->value_len);
        return;
    }

    if (record->value_len > MAX_VALUE_SIZE) {
        hpkv_log(HPKV_LOG_ERR, "Record value length exceeds maximum. Key: %.*s, Value length: %zu\n", 
                 record->key_len, record->key, record->value_len);
        return;
    }

    hpkv_log(HPKV_LOG_DEBUG, "Writing record to disk. Key: %.*s, Value length: %zu\n", 
             record->key_len, record->key, record->value_len);

    device_size = i_size_read(bdev->bd_inode);

    // Calculate how many sectors we need for this record
    size_t total_record_size = calculate_record_size(record->key_len, record->value_len);
    required_sectors = DIV_ROUND_UP(total_record_size, HPKV_BLOCK_SIZE);

    // Find free sectors
    record->sector = find_free_sector(required_sectors * HPKV_BLOCK_SIZE);
    if (record->sector == -ENOSPC) {
        // No free sector available, extend the device
        new_size = device_size + max(EXTENSION_SIZE, (loff_t)required_sectors * HPKV_BLOCK_SIZE);
        
        // Check if the new size exceeds the maximum allowed size
        if (new_size > MAX_DEVICE_SIZE) {
            if (device_size < MAX_DEVICE_SIZE) {
                new_size = MAX_DEVICE_SIZE;
            } else {
                hpkv_log(HPKV_LOG_ERR, "Device already at maximum size. Cannot extend further. Key: %.*s\n", record->key_len, record->key);
                return;
            }
        }

        // Extend the device size
        if (extend_device(new_size) != 0) {
            hpkv_log(HPKV_LOG_ERR, "Failed to extend device. Writing aborted. Key: %.*s\n", record->key_len, record->key);
            return;
        }

        // Update device_size after extension
        device_size = i_size_read(bdev->bd_inode);

        // Retry finding free sectors after extension
        record->sector = find_free_sector(required_sectors * HPKV_BLOCK_SIZE);
        if (record->sector == -ENOSPC) {
            hpkv_log(HPKV_LOG_ERR, "No free sector available after extension. Key: %.*s\n", record->key_len, record->key);
            return;
        }
    }

    // Allocate a buffer for the entire record
    write_buffer = vmalloc(required_sectors * HPKV_BLOCK_SIZE);
    if (!write_buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate write buffer. Key: %.*s\n", record->key_len, record->key);
        return;
    }

    // Prepare the write buffer
    memcpy(write_buffer, &record->key_len, sizeof(uint16_t));
    memcpy(write_buffer + sizeof(uint16_t), record->key, record->key_len);
    memcpy(write_buffer + sizeof(uint16_t) + record->key_len, &record->value_len, sizeof(size_t));
    memcpy(write_buffer + sizeof(uint16_t) + record->key_len + sizeof(size_t), record->value, record->value_len);

    // Write to disk
    for (i = 0; i < required_sectors; i++) {
        bh = __getblk(bdev, record->sector + i, HPKV_BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer head for writing. Key: %.*s, Sector: %llu\n", 
                     record->key_len, record->key, (unsigned long long)(record->sector + i));
            vfree(write_buffer);
            return;
        }

        lock_buffer(bh);
        memcpy(bh->b_data, write_buffer + (i * HPKV_BLOCK_SIZE), HPKV_BLOCK_SIZE);
        set_buffer_uptodate(bh);
        mark_buffer_dirty(bh);
        unlock_buffer(bh);
        ret = sync_dirty_buffer(bh);
        if (ret < 0) {
            hpkv_log(HPKV_LOG_ERR, "Failed to sync buffer to disk. Key: %.*s, Sector: %llu\n", 
                     record->key_len, record->key, (unsigned long long)(record->sector + i));
        }
        brelse(bh);
    }

    vfree(write_buffer);

    // Successfully written to disk, now free the in-memory value
    if (record->value) {
        kfree(record->value);
        record->value = NULL;
        smp_wmb();  // Ensure the NULL is visible to other CPUs
    }

    hpkv_log(HPKV_LOG_INFO, "Successfully wrote record to disk: key=%.*s, sector=%llu, value_len=%zu, sectors=%d\n", 
             record->key_len, record->key, (unsigned long long)record->sector, record->value_len, required_sectors);

    // Update the bitmap after writing
    spin_lock(&sector_allocation_lock);
    for (i = 0; i < required_sectors; i++) {
        set_bit(record->sector + i, allocated_sectors);
    }
    smp_mb();  // Memory barrier after bit operations
    spin_unlock(&sector_allocation_lock);
}

static void mark_sectors_as_deleted(sector_t start_sector, int num_sectors)
{
    struct buffer_head *bh;
    int i;

    for (i = 0; i < num_sectors; i++) {
        bh = __getblk(bdev, start_sector + i, HPKV_BLOCK_SIZE);
        if (bh) {
            lock_buffer(bh);
            memset(bh->b_data, 0, HPKV_BLOCK_SIZE);
            memcpy(bh->b_data, "\0DELETED", 8);
            set_buffer_uptodate(bh);
            mark_buffer_dirty(bh);
            unlock_buffer(bh);
            sync_dirty_buffer(bh);
            brelse(bh);
        }
    }
}

static void flush_write_buffer(void)
{
    struct write_buffer_entry *entry, *tmp;
    LIST_HEAD(local_list);
    int records_changed = 0;
    long size_changed = 0;
    unsigned long timeout;

    if (atomic_cmpxchg(&flush_running, 0, 1) != 0) {
        hpkv_log(HPKV_LOG_INFO, "Flush already in progress, waiting for completion\n");
        wait_for_completion_timeout(&flush_completion, msecs_to_jiffies(10000));
        if (atomic_read(&flush_running) != 0) {
            hpkv_log(HPKV_LOG_WARNING, "Flush operation timed out, forcing completion\n");
            complete(&flush_completion);
        }
        return;
    }

    reinit_completion(&flush_completion);

    hpkv_log(HPKV_LOG_INFO, "Starting flush_write_buffer\n");

    spin_lock(&write_buffer_lock);
    list_splice_init(&write_buffer, &local_list);
    spin_unlock(&write_buffer_lock);

    list_for_each_entry_safe(entry, tmp, &local_list, list) {
        if (!entry || !entry->record) {
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        init_completion(&entry->work_done);
        atomic_set(&entry->work_status, 0);
        queue_work(flush_wq, &entry->work);

        timeout = wait_for_completion_timeout(&entry->work_done, msecs_to_jiffies(WORK_TIMEOUT_MS));
        if (timeout == 0) {
            hpkv_log(HPKV_LOG_WARNING, "Work item timed out for key: %.*s\n", entry->record->key_len, entry->record->key);
            cancel_work_sync(&entry->work);
        }

        if (atomic_read(&entry->work_status) == 2) {  // Completed successfully
            switch (entry->op) {
                case OP_INSERT:
                    records_changed++;
                    size_changed += entry->record->value_len;
                    break;
                case OP_UPDATE:
                    size_changed += (long)entry->record->value_len - (long)entry->old_value_len;
                    break;
                case OP_DELETE:
                    records_changed--;
                    size_changed -= entry->old_value_len;
                    break;
            }
        }

        list_del(&entry->list);
        kfree(entry);
    }

    if (records_changed != 0 || size_changed != 0) {
        update_metadata();
    }

    atomic_set(&flush_running, 0);
    complete(&flush_completion);
    hpkv_log(HPKV_LOG_INFO, "Finished flush operations\n");
}

static int write_buffer_worker(void *data)
{
    unsigned long next_flush = jiffies + WRITE_BUFFER_FLUSH_INTERVAL;

    while (!kthread_should_stop() && !write_buffer_exit) {
        long ret = wait_event_interruptible_timeout(write_buffer_wait, 
                                         kthread_should_stop() || write_buffer_size() >= WRITE_BUFFER_SIZE,
                                         WRITE_BUFFER_FLUSH_INTERVAL);
        
        if (kthread_should_stop()) {
            break;
        }

        if (ret == 0) {
            hpkv_log(HPKV_LOG_DEBUG, "Write buffer worker woke up due to timeout\n");
        } else if (ret > 0) {
            hpkv_log(HPKV_LOG_DEBUG, "Write buffer worker woke up due to buffer size threshold\n");
        } else {
            hpkv_log(HPKV_LOG_WARNING, "Write buffer worker interrupted\n");
            continue;
        }

        // Flush if buffer size threshold is reached or time interval has passed
        if (write_buffer_size() >= WRITE_BUFFER_SIZE || (time_after_eq(jiffies, next_flush) && write_buffer_size() > 0)) {
            hpkv_log(HPKV_LOG_INFO, "Starting write buffer flush at jiffies: %lu\n", jiffies);
            // Check if flush_wq is initialized before queueing work
            if (flush_wq) {
                queue_work(flush_wq, &hpkv_flush_work);
                next_flush = jiffies + WRITE_BUFFER_FLUSH_INTERVAL;
                hpkv_log(HPKV_LOG_INFO, "Queued write buffer flush at jiffies: %lu\n", jiffies);
            } else {
                hpkv_log(HPKV_LOG_WARNING, "Flush workqueue not initialized, skipping flush\n");
            }
        }
    }

    return 0;
}

static void flush_work_handler(struct work_struct *work)
{
    flush_write_buffer();
}

static void write_record_work(struct work_struct *work)
{
    struct write_buffer_entry *entry = container_of(work, struct write_buffer_entry, work);
    unsigned long timeout;
    
    if (!entry) {
        hpkv_log(HPKV_LOG_ERR, "Invalid entry in write_record_work\n");
        return;
    }

    atomic_set(&entry->work_status, 1);  // Mark as in progress

    timeout = jiffies + msecs_to_jiffies(5000);  // 5 second timeout

    if (!entry->record) {
        hpkv_log(HPKV_LOG_ERR, "Invalid record in write_record_work\n");
        atomic_set(&entry->work_status, 3);  // Mark as failed
        complete(&entry->work_done);
        return;
    }

    switch (entry->op) {
        case OP_INSERT:
        case OP_UPDATE:
            if (atomic_read(&entry->record->refcount) > 0) {
                // If refcount is greater than 0, write to disk
                write_record_to_disk(entry->record);
                hpkv_log(HPKV_LOG_INFO, "Wrote record to disk: %.*s\n", entry->record->key_len, entry->record->key);
            }
            break;
        case OP_DELETE:
            if (entry->record->sector != 0) {
                size_t total_record_size = calculate_record_size(entry->record->key_len, entry->old_value_len);
                int num_sectors = DIV_ROUND_UP(total_record_size, HPKV_BLOCK_SIZE);
                mark_sectors_as_deleted(entry->record->sector, num_sectors);
                release_sectors(entry->record->sector, num_sectors);
                hpkv_log(HPKV_LOG_INFO, "Marked %d sectors as deleted for key: %.*s\n", 
                         num_sectors, entry->record->key_len, entry->record->key);
            }
            // Free the record
            call_rcu(&entry->record->rcu, record_free_rcu);
            hpkv_log(HPKV_LOG_INFO, "Scheduled record for freeing: %.*s\n", entry->record->key_len, entry->record->key);
            break;
    }

    if (time_after(jiffies, timeout)) {
        hpkv_log(HPKV_LOG_WARNING, "Write operation timed out for key: %.*s\n", entry->record->key_len, entry->record->key);
        atomic_set(&entry->work_status, 3);  // Mark as timed out
    } else {
        atomic_set(&entry->work_status, 2);  // Mark as completed
    }

    complete(&entry->work_done);
}

static void metadata_update_work_func(struct work_struct *work)
{
    update_metadata();
}

static void compact_disk(void)
{
    // Check if flush is in progress
    if (atomic_read(&flush_running) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Flush operation in progress, cannot start compaction\n");
        return;
    }


    if (atomic_read(&purge_in_progress) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Purge operation in progress, skipping compact operation\n");
        return;
    }

    // Set compact_in_progress flag
    if (atomic_cmpxchg(&compact_in_progress, 0, 1) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Compact operation already in progress\n");
        return;
    }

    // Flush write buffer before compaction
    flush_write_buffer();

    struct record *record;
    sector_t read_sector = 1, write_sector = 1;
    char *buffer;
    struct buffer_head *read_bh, *write_bh;
    sector_t total_sectors;

    percpu_down_write(&rw_sem);

    total_sectors = i_size_read(bdev->bd_inode) / HPKV_BLOCK_SIZE;
    hpkv_log(HPKV_LOG_INFO, "Starting disk compaction. Total sectors: %llu\n", (unsigned long long)total_sectors);

    buffer = vmalloc(HPKV_BLOCK_SIZE);
    if (!buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer for disk compaction\n");
        goto out;
    }

    while (read_sector < total_sectors) {
        read_bh = __bread(bdev, read_sector, HPKV_BLOCK_SIZE);
        if (!read_bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read sector %llu during compaction\n", (unsigned long long)read_sector);
            read_sector++;
            continue;
        }

        smp_rmb();  // Memory barrier before reading record data
        // Check if the record is deleted (first byte of key is 0)
        if (read_bh->b_data[0] != '\0') {
            // Record is not deleted, so we need to keep it
            if (read_sector != write_sector) {
                write_bh = __getblk(bdev, write_sector, HPKV_BLOCK_SIZE);
                if (!write_bh) {
                    hpkv_log(HPKV_LOG_ERR, "Failed to get block for writing during compaction\n");
                    brelse(read_bh);
                    read_sector++;
                    continue;
                }

                memcpy(write_bh->b_data, read_bh->b_data, HPKV_BLOCK_SIZE);
                mark_buffer_dirty(write_bh);
                sync_dirty_buffer(write_bh);

                // Update the sector in the in-memory record and bitmap
                char key[MAX_KEY_SIZE];
                memcpy(key, read_bh->b_data, MAX_KEY_SIZE);
                record = search_record_in_memory(key, MAX_KEY_SIZE);
                if (record) {
                    spin_lock(&sector_allocation_lock);
                    int sectors_used = (record->value_len + HPKV_BLOCK_SIZE - 1) / HPKV_BLOCK_SIZE;
                    for (int i = 0; i < sectors_used; i++) {
                        clear_bit(record->sector + i, allocated_sectors);
                        set_bit(write_sector + i, allocated_sectors);
                    }
                    smp_mb();  // Memory barrier after bit operations
                    spin_unlock(&sector_allocation_lock);
                    smp_wmb();  // Memory barrier before updating record sector
                    record->sector = write_sector;
                }

                brelse(write_bh);
            }
            write_sector++;
        } else {
            // Clear the bit for deleted or empty sectors
            spin_lock(&sector_allocation_lock);
            clear_bit(read_sector, allocated_sectors);
            smp_mb();  // Memory barrier after bit operations
            spin_unlock(&sector_allocation_lock);
        }

        brelse(read_bh);
        read_sector++;
    }

    vfree(buffer);

    // Truncate the device to the new size
    sector_t new_size = write_sector * HPKV_BLOCK_SIZE;
    loff_t old_size = i_size_read(bdev->bd_inode);
    
    hpkv_log(HPKV_LOG_INFO, "Compaction: Old size: %lld, New size: %llu\n", 
             old_size, (unsigned long long)new_size);

    if (new_size < old_size) {
        i_size_write(bdev->bd_inode, new_size);
        sync_blockdev(bdev);
        hpkv_log(HPKV_LOG_INFO, "Device shrunk from %lld to %llu bytes\n", 
                 old_size, (unsigned long long)new_size);
        
        // Update the bitmap to reflect the new size
        spin_lock(&sector_allocation_lock);
        bitmap_clear(allocated_sectors, new_size / HPKV_BLOCK_SIZE, (old_size - new_size) / HPKV_BLOCK_SIZE);
        smp_mb();  // Memory barrier after bit operations
        spin_unlock(&sector_allocation_lock);

        // Update the metadata with the new size
        update_metadata_size(new_size);
    } else {
        hpkv_log(HPKV_LOG_WARNING, "New size (%llu) not smaller than old size (%lld), skipping shrink\n", 
                 (unsigned long long)new_size, old_size);
    }

    hpkv_log(HPKV_LOG_INFO, "Disk compaction completed. New size: %llu sectors\n", (unsigned long long)write_sector);

out:
    percpu_up_write(&rw_sem);
    atomic_set(&compact_in_progress, 0);
}

static int calculate_fragmentation(void)
{
    struct record *record;
    struct rb_node *node;
    sector_t next_expected_sector = 1;  // Start from sector 1
    sector_t current_sector;
    sector_t total_sectors = i_size_read(bdev->bd_inode) / HPKV_BLOCK_SIZE;
    long total_used_space = 0;
    long total_empty_space = 0;

    rcu_read_lock();
    for (node = rb_first(&records_tree); node; node = rb_next(node)) {
        record = rb_entry(node, struct record, tree_node);
        current_sector = READ_ONCE(record->sector);

        if (current_sector > next_expected_sector) {
            total_empty_space += (current_sector - next_expected_sector) * HPKV_BLOCK_SIZE;
        }

        // Calculate the number of sectors this record occupies
        sector_t record_sectors = (READ_ONCE(record->value_len) + HPKV_BLOCK_SIZE - 1) / HPKV_BLOCK_SIZE;
        total_used_space += record_sectors * HPKV_BLOCK_SIZE;
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
        total_empty_space += (total_sectors - next_expected_sector) * HPKV_BLOCK_SIZE;
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
        int len = snprintf(temp_buffer, MAX_KEY_SIZE + MAX_VALUE_SIZE + 2, "%.*s:%s\n", (int)record->key_len, record->key, record->value);
        
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

    char *buffer = kmalloc(size, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    if (copy_from_user(buffer, user_buffer, size)) {
        kfree(buffer);
        return -EFAULT;
    }

    char *sep = memchr(buffer, ':', size);
    if (!sep) {
        kfree(buffer);
        return -EINVAL;
    }

    uint16_t key_len = sep - buffer;
    size_t value_len = size - key_len - 1;  // -1 for the separator

    if (key_len >= MAX_KEY_SIZE || value_len >= MAX_VALUE_SIZE) {
        kfree(buffer);
        return -EMSGSIZE;
    }

    // Check if this is a partial update
    bool is_partial_update = false;
    if (sep[1] == '+') {
        is_partial_update = true;
        sep++;  // Move past the '+' character
        value_len--;  // Adjust value length
    }

    int ret = insert_or_update_record(buffer, key_len, sep + 1, value_len, is_partial_update);
    kfree(buffer);

    if (ret)
        return ret;

    *offset += size;
    return size;
}

static int purge_data(void)
{
    // Check if flush is in progress
    if (atomic_read(&flush_running) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Flush operation in progress, cannot start purge\n");
        return -EBUSY;
    }

    // Check if compact is in progress
    if (atomic_read(&compact_in_progress) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Compact operation in progress, cannot start purge\n");
        return -EBUSY;
    }

    // Set purge_in_progress flag
    if (atomic_cmpxchg(&purge_in_progress, 0, 1) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Purge operation already in progress\n");
        return -EBUSY;
    }

    sector_t sector = 1;
    struct buffer_head *bh;
    int ret = 0;
    char *empty_buffer;
    unsigned long flags;
    struct rb_node *node, *next;
    struct record *record;
    struct write_buffer_entry *entry, *tmp;
    LIST_HEAD(local_list);

    hpkv_log(HPKV_LOG_INFO, "Starting purge operation\n");

    // Allocate an empty buffer once
    empty_buffer = kzalloc(HPKV_BLOCK_SIZE, GFP_KERNEL);
    if (!empty_buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for purge operation\n");
        atomic_set(&purge_in_progress, 0);
        return -ENOMEM;
    }
    memcpy(empty_buffer, "\0DELETED", 8);  // Mark as deleted

    // Use a write lock for the entire operation to prevent concurrent access
    percpu_down_write(&rw_sem);

    // Clear in-memory data structures first
    rcu_read_lock();
    hash_init(kv_store);  // This effectively clears the hash table
    rcu_read_unlock();

    // Clear the red-black tree
    for (node = rb_first(&records_tree); node; node = next) {
        next = rb_next(node);
        record = rb_entry(node, struct record, tree_node);
        rb_erase(node, &records_tree);
        call_rcu(&record->rcu, record_free_rcu);
    }

    atomic_long_set(&total_disk_usage, 0);
    atomic_set(&record_count, 0);

    // Clear cache
    spin_lock_irqsave(&cache_lock, flags);
    {
        int bkt;
        struct hlist_node *tmp;
        struct cached_record *cached;

        hash_for_each_safe(cache, bkt, tmp, cached, node) {
            hash_del(&cached->node);
            if (cached->value) {
                kfree(cached->value);
                cached->value = NULL;
            }
            kfree(cached);
        }
        atomic_set(&cache_count, 0);
    }
    spin_unlock_irqrestore(&cache_lock, flags);

    hpkv_log(HPKV_LOG_INFO, "In-memory structures cleared\n");

    // Clear the write buffer
    spin_lock(&write_buffer_lock);
    list_splice_init(&write_buffer, &local_list);
    spin_unlock(&write_buffer_lock);

    list_for_each_entry_safe(entry, tmp, &local_list, list) {
        list_del(&entry->list);
        if (entry->record) {
            call_rcu(&entry->record->rcu, record_free_rcu);
        }
        kfree(entry);
    }

    hpkv_log(HPKV_LOG_INFO, "Write buffer cleared\n");

    // Clear the bitmap
    spin_lock(&sector_allocation_lock);
    bitmap_zero(allocated_sectors, SECTORS_BITMAP_SIZE);
    set_bit(0, allocated_sectors);  // Mark metadata sector as allocated
    smp_mb();  // Memory barrier after bit operations
    spin_unlock(&sector_allocation_lock);

    // Now clear the disk
    while (sector * HPKV_BLOCK_SIZE < i_size_read(bdev->bd_inode)) {
        bh = __getblk(bdev, sector, HPKV_BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to get block for purging at sector %llu\n", (unsigned long long)sector);
            ret = -EIO;
            goto out;
        }

        lock_buffer(bh);
        memcpy(bh->b_data, empty_buffer, HPKV_BLOCK_SIZE);
        set_buffer_uptodate(bh);
        mark_buffer_dirty(bh);
        unlock_buffer(bh);
        
        if (sector % 1000 == 0) {  // Sync every 1000 sectors to avoid overwhelming I/O
            sync_dirty_buffer(bh);
            hpkv_log(HPKV_LOG_INFO, "Purged %llu sectors\n", (unsigned long long)sector);
            
            // Allow other processes to run
            percpu_up_write(&rw_sem);
            cond_resched();
            percpu_down_write(&rw_sem);
        }
        
        brelse(bh);
        sector++;

        if (signal_pending(current)) {
            hpkv_log(HPKV_LOG_WARNING, "Purge operation interrupted\n");
            ret = -EINTR;
            goto out;
        }
    }

    // Final sync
    sync_blockdev(bdev);

    ret = update_metadata();
    if (ret < 0) {
        hpkv_log(HPKV_LOG_ERR, "Failed to update metadata after purge\n");
    } else {
        hpkv_log(HPKV_LOG_INFO, "Metadata updated successfully after purge\n");
    }

out:
    kfree(empty_buffer);
    percpu_up_write(&rw_sem);
    synchronize_rcu();
    atomic_set(&purge_in_progress, 0);
    hpkv_log(HPKV_LOG_INFO, "Purge operation completed with status %d\n", ret);
    return ret;
}

static int load_indexes(void)
{
    struct buffer_head *bh;
    struct hpkv_metadata metadata;
    sector_t sector = 1;  // Start from sector 1, as sector 0 is reserved for metadata
    char *buffer;
    loff_t device_size, read_size;
    bool corruption_detected = false;
    int ret = 0;

    percpu_down_write(&rw_sem);

    hpkv_log(HPKV_LOG_INFO, "Loading indexes\n");

    // Read the metadata block (sector 0)
    bh = __bread(bdev, HPKV_METADATA_BLOCK, HPKV_BLOCK_SIZE);
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
    hpkv_log(HPKV_LOG_INFO, "Total records: %llu, Total size: %llu bytes, Device size: %llu bytes, Version: %u\n", 
           metadata.total_records, metadata.total_size, metadata.device_size, metadata.version);

    device_size = i_size_read(bdev->bd_inode);
    hpkv_log(HPKV_LOG_INFO, "Current device size: %lld bytes\n", device_size);

    // Determine how much of the disk to read
    if (force_read_disk) {
        read_size = device_size;
        hpkv_log(HPKV_LOG_INFO, "Force reading entire disk: %lld bytes\n", read_size);
    } else {
        read_size = min_t(loff_t, metadata.device_size, device_size);
        hpkv_log(HPKV_LOG_INFO, "Reading up to metadata device size: %lld bytes\n", read_size);
    }

    buffer = vmalloc(HPKV_BLOCK_SIZE);
    if (!buffer) {
        hpkv_log(HPKV_LOG_ERR, "Failed to allocate buffer for load_indexes\n");
        ret = -ENOMEM;
        goto out;
    }

    while (sector * HPKV_BLOCK_SIZE < read_size) {
        hpkv_log(HPKV_LOG_INFO, "Reading sector %llu\n", (unsigned long long)sector);
        
        bh = __bread(bdev, sector, HPKV_BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read block at sector %llu\n", (unsigned long long)sector);
            sector++;
            continue;
        }

        memcpy(buffer, bh->b_data, HPKV_BLOCK_SIZE);
        
        // Read the key length
        uint16_t key_len;
        memcpy(&key_len, buffer, sizeof(uint16_t));

        // Read the key
        char *key = kmalloc(key_len, GFP_KERNEL);
        if (!key) {
            brelse(bh);
            vfree(buffer);
            ret = -ENOMEM;
            goto out;
        }
        memcpy(key, buffer + sizeof(uint16_t), key_len);

        // Read the value length
        size_t value_len;
        memcpy(&value_len, buffer + sizeof(uint16_t) + key_len, sizeof(size_t));

        hpkv_log(HPKV_LOG_INFO, "Processing key: %.*s, value length: %zu\n", key_len, key, value_len);

        if (key[0] != '\0' && value_len > 0 && value_len <= MAX_VALUE_SIZE) {
            struct record *record = kmem_cache_alloc(record_cache, GFP_KERNEL);
            if (record) {
                record->key = kmalloc(key_len, GFP_KERNEL);
                if (!record->key) {
                    kmem_cache_free(record_cache, record);
                    hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for key\n");
                    sector++;
                    brelse(bh);
                    kfree(key);
                    continue;
                }
                memcpy(record->key, key, key_len);
                record->key_len = key_len;
                record->value = NULL;  // Value will be loaded from disk on demand
                record->value_len = value_len;
                record->sector = sector;
                
                u32 hash = djb2_hash(key, key_len);
                atomic_set(&record->refcount, 1);
                smp_wmb();  // Memory barrier before making the record visible

                hash_add_rcu(kv_store, &record->hash_node, hash);
                insert_rb_tree(record);
                atomic_long_add(value_len, &total_disk_usage);
                atomic_inc(&record_count);
                
                // Mark the sectors as allocated in the bitmap
                int sectors_used = (value_len + HPKV_BLOCK_SIZE - 1) / HPKV_BLOCK_SIZE;
                spin_lock(&sector_allocation_lock);
                for (int i = 0; i < sectors_used; i++) {
                    set_bit(sector + i, allocated_sectors);
                }
                smp_mb();  // Memory barrier after bit operations
                spin_unlock(&sector_allocation_lock);
                
                hpkv_log(HPKV_LOG_INFO, "Added record for key: %.*s\n", key_len, key);
            } else {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for record\n");
            }
        } else if (key[0] == '\0') {
            // This is a deleted or empty record, skip it
            hpkv_log(HPKV_LOG_INFO, "Skipping deleted or empty record at sector %llu\n", (unsigned long long)sector);
        } else {
            hpkv_log(HPKV_LOG_WARNING, "Invalid record found at sector %llu. Key: %.*s, Value length: %zu\n", 
                   (unsigned long long)sector, key_len, key, value_len);
            corruption_detected = true;
            break;  // Stop processing further to avoid potential issues with corrupted data
        }

        brelse(bh);
        kfree(key);
        sector++;
    }

    vfree(buffer);

    // After loading all records from disk, process any pending write buffer entries
    struct write_buffer_entry *entry, *tmp;
    spin_lock(&write_buffer_lock);
    list_for_each_entry_safe(entry, tmp, &write_buffer, list) {
        // Update in-memory structures with the buffered record
        hash_add_rcu(kv_store, &entry->record->hash_node, djb2_hash(entry->record->key, entry->record->key_len));
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
    char *key = NULL;
    char *value = NULL;
    uint16_t key_len;
    size_t value_len;
    int ret;

    switch (cmd) {
        case HPKV_IOCTL_INSERT:
            if (!arg || !access_ok((void __user *)arg, sizeof(uint16_t) + sizeof(size_t))) {
                hpkv_log(HPKV_LOG_ERR, "Invalid user space pointer for INSERT\n");
                return -EFAULT;
            }
            
            if (copy_from_user(&key_len, (void __user *)arg, sizeof(uint16_t)) ||
                copy_from_user(&value_len, (void __user *)(arg + sizeof(uint16_t)), sizeof(size_t))) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy lengths from user space for INSERT\n");
                return -EFAULT;
            }

            hpkv_log(HPKV_LOG_DEBUG, "Received INSERT command - Key length: %u, Value length: %zu\n", key_len, value_len);

            if (key_len == 0 || key_len > MAX_KEY_SIZE || value_len == 0 || value_len > MAX_VALUE_SIZE) {
                hpkv_log(HPKV_LOG_ERR, "Invalid key length: %u or value length: %zu for INSERT\n", key_len, value_len);
                return -EINVAL;
            }

            key = kmalloc(key_len, GFP_KERNEL);
            value = kmalloc(value_len, GFP_KERNEL);
            if (!key || !value) {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for key or value in INSERT\n");
                kfree(key);
                kfree(value);
                return -ENOMEM;
            }

            if (copy_from_user(key, (char __user *)(arg + sizeof(uint16_t) + sizeof(size_t)), key_len) ||
                copy_from_user(value, (char __user *)(arg + sizeof(uint16_t) + sizeof(size_t) + key_len), value_len)) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy key or value from user space for INSERT\n");
                kfree(key);
                kfree(value);
                return -EFAULT;
            }

            hpkv_log(HPKV_LOG_INFO, "Received INSERT command for key: %.*s (length: %u)\n", key_len, key, key_len);
            ret = insert_or_update_record(key, key_len, value, value_len, false);
            if (ret == 0) {
                hpkv_log(HPKV_LOG_INFO, "INSERT successful for key: %.*s (length: %u)\n", key_len, key, key_len);
            } else {
                hpkv_log(HPKV_LOG_ERR, "INSERT failed for key: %.*s (length: %u), error: %d\n", key_len, key, key_len, ret);
            }
            kfree(key);
            kfree(value);
            return ret;

        case HPKV_IOCTL_GET:  // Get by exact key
            if (!arg || !access_ok((void __user *)arg, sizeof(uint16_t) + sizeof(size_t))) {
                hpkv_log(HPKV_LOG_ERR, "Invalid user space pointer\n");
                return -EFAULT;
            }
            
            if (copy_from_user(&key_len, (void __user *)arg, sizeof(uint16_t))) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy key length from user space\n");
                return -EFAULT;
            }

            if (key_len == 0 || key_len > MAX_KEY_SIZE) {
                hpkv_log(HPKV_LOG_ERR, "Invalid key length: %u\n", key_len);
                return -EINVAL;
            }

            key = kmalloc(key_len, GFP_KERNEL);
            if (!key) {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for key\n");
                return -ENOMEM;
            }

            if (copy_from_user(key, (char __user *)(arg + sizeof(uint16_t)), key_len)) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy key from user space\n");
                kfree(key);
                return -EFAULT;
            }

            hpkv_log(HPKV_LOG_DEBUG, "Searching for key: %.*s (length: %u)\n", key_len, key, key_len);
            
            ret = search_record(key, key_len, &value, &value_len);
            if (ret == 0) {
                if (!value || value_len == 0) {
                    hpkv_log(HPKV_LOG_ERR, "search_record returned success but value is NULL or empty\n");
                    kfree(key);
                    kfree(value);
                    return -EFAULT;
                }
                
                // Copy the value length to user space
                if (copy_to_user((char __user *)(arg + sizeof(uint16_t)), &value_len, sizeof(size_t))) {
                    hpkv_log(HPKV_LOG_ERR, "Failed to copy value length to user space\n");
                    kfree(key);
                    kfree(value);
                    return -EFAULT;
                }
                
                // Copy the actual value to user space
                if (copy_to_user((char __user *)(arg + sizeof(uint16_t) + sizeof(size_t)), value, value_len)) {
                    hpkv_log(HPKV_LOG_ERR, "Failed to copy value to user space\n");
                    kfree(key);
                    kfree(value);
                    return -EFAULT;
                }
                
                hpkv_log(HPKV_LOG_DEBUG, "Retrieved value for key %.*s (length: %zu)\n", 
                         key_len, key, value_len);
                
                kfree(key);
                kfree(value);
                return 0;  // Return success
            } else if (ret == -ENOENT) {
                hpkv_log(HPKV_LOG_DEBUG, "Key not found: %.*s (length: %u)\n", key_len, key, key_len);
                kfree(key);
                return -ENOENT;
            } else {
                hpkv_log(HPKV_LOG_ERR, "search_record failed with error %d for key: %.*s (length: %u)\n", ret, key_len, key, key_len);
                kfree(key);
                return ret;
            }
        
        case HPKV_IOCTL_DELETE:  // Delete by key
            if (!arg || !access_ok((void __user *)arg, sizeof(uint16_t))) {
                hpkv_log(HPKV_LOG_ERR, "Invalid user space pointer\n");
                return -EFAULT;
            }
            
            if (copy_from_user(&key_len, (void __user *)arg, sizeof(uint16_t))) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy key length from user space\n");
                return -EFAULT;
            }

            if (key_len == 0 || key_len > MAX_KEY_SIZE) {
                hpkv_log(HPKV_LOG_ERR, "Invalid key length: %u\n", key_len);
                return -EINVAL;
            }

            key = kmalloc(key_len, GFP_KERNEL);
            if (!key) {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for key\n");
                return -ENOMEM;
            }

            if (copy_from_user(key, (char __user *)(arg + sizeof(uint16_t)), key_len)) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy key from user space\n");
                kfree(key);
                return -EFAULT;
            }

            hpkv_log(HPKV_LOG_DEBUG, "Deleting key: %.*s (length: %u)\n", key_len, key, key_len);
            ret = delete_record(key, key_len);
            kfree(key);
            return ret;

        case HPKV_IOCTL_PARTIAL_UPDATE:  // Partial update
            hpkv_log(HPKV_LOG_DEBUG, "Entering partial update ioctl\n");
            if (!arg || !access_ok((void __user *)arg, sizeof(uint16_t) + sizeof(size_t))) {
                hpkv_log(HPKV_LOG_ERR, "Invalid user space pointer\n");
                return -EFAULT;
            }
            
            if (copy_from_user(&key_len, (void __user *)arg, sizeof(uint16_t)) ||
                copy_from_user(&value_len, (void __user *)(arg + sizeof(uint16_t)), sizeof(size_t))) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy lengths from user space\n");
                return -EFAULT;
            }

            hpkv_log(HPKV_LOG_DEBUG, "Received key length: %u, value length: %zu\n", key_len, value_len);

            if (key_len == 0 || key_len > MAX_KEY_SIZE || value_len == 0 || value_len > MAX_VALUE_SIZE) {
                hpkv_log(HPKV_LOG_ERR, "Invalid key length: %u or value length: %zu\n", key_len, value_len);
                return -EINVAL;
            }

            key = kmalloc(key_len, GFP_KERNEL);
            value = kmalloc(value_len, GFP_KERNEL);
            if (!key || !value) {
                hpkv_log(HPKV_LOG_ERR, "Failed to allocate memory for key or value\n");
                kfree(key);
                kfree(value);
                return -ENOMEM;
            }

            if (copy_from_user(key, (char __user *)(arg + sizeof(uint16_t) + sizeof(size_t)), key_len) ||
                copy_from_user(value, (char __user *)(arg + sizeof(uint16_t) + sizeof(size_t) + key_len), value_len)) {
                hpkv_log(HPKV_LOG_ERR, "Failed to copy key or value from user space\n");
                kfree(key);
                kfree(value);
                return -EFAULT;
            }

            hpkv_log(HPKV_LOG_INFO, "Received partial update ioctl command for key: %.*s (length: %u)\n", key_len, key, key_len);
            ret = insert_or_update_record(key, key_len, value, value_len, true);
            if (ret == 0) {
                hpkv_log(HPKV_LOG_INFO, "Partial update successful for key: %.*s (length: %u)\n", key_len, key, key_len);
            } else {
                hpkv_log(HPKV_LOG_ERR, "Partial update failed for key: %.*s (length: %u), error: %d\n", key_len, key, key_len, ret);
            }
            kfree(key);
            kfree(value);
            return ret;

        case HPKV_IOCTL_PURGE:  // Purge all data
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
    seq_printf(m, "Device size: %lld bytes\n", i_size_read(bdev->bd_inode));
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

    bh = __getblk(bdev, HPKV_METADATA_BLOCK, HPKV_BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to get block for initialization\n");
        return -EIO;
    }

    memset(&metadata, 0, sizeof(struct hpkv_metadata));
    memcpy(metadata.signature, HPKV_SIGNATURE, HPKV_SIGNATURE_SIZE);
    metadata.total_records = 0;
    metadata.total_size = 0;
    metadata.device_size = i_size_read(bdev->bd_inode);  // Set the initial device size
    metadata.version = 1;  // Initial version

    lock_buffer(bh);
    memset(bh->b_data, 0, HPKV_BLOCK_SIZE);  // Clear the block first
    memcpy(bh->b_data, &metadata, sizeof(struct hpkv_metadata));
    set_buffer_uptodate(bh);
    mark_buffer_dirty(bh);
    unlock_buffer(bh);
    
    ret = sync_dirty_buffer(bh);
    if (ret) {
        hpkv_log(HPKV_LOG_ERR, "Failed to sync metadata block\n");
    }
    
    brelse(bh);

    hpkv_log(HPKV_LOG_INFO, "Device initialized with size: %llu bytes\n", metadata.device_size);

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
        bh = __bread(bdev, i, HPKV_BLOCK_SIZE);
        if (!bh) {
            hpkv_log(HPKV_LOG_ERR, "Failed to read block %d while checking if disk is empty\n", i);
            return false;  // Assume not empty if we can't read
        }

        if (!is_zero_buffer(bh->b_data, HPKV_BLOCK_SIZE)) {
            is_empty = false;
            brelse(bh);
            break;
        }

        brelse(bh);
    }

    return is_empty;
}

static int check_metadata(struct hpkv_metadata *metadata)
{
    struct buffer_head *bh;
    int ret = 0;

    bh = __bread(bdev, HPKV_METADATA_BLOCK, HPKV_BLOCK_SIZE);
    if (!bh) {
        hpkv_log(HPKV_LOG_ERR, "Failed to read metadata block\n");
        return -EIO;
    }

    memcpy(metadata, bh->b_data, sizeof(struct hpkv_metadata));
    brelse(bh);
    bh = NULL;

    if (memcmp(metadata->signature, HPKV_SIGNATURE, HPKV_SIGNATURE_SIZE) != 0) {
        hpkv_log(HPKV_LOG_WARNING, "Invalid signature found\n");
        ret = -EINVAL;
    }

    return ret;
}

static int __init hpkv_init(void)
{
    int ret;
    struct hpkv_metadata metadata;

    hpkv_log(HPKV_LOG_INFO, "Initializing module\n");
    hpkv_log(HPKV_LOG_INFO, "Mount path received: %s\n", mount_path);

    major_num = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_num < 0) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to register a major number\n");
        return major_num;
    }

    record_cache = kmem_cache_create("hpkv_record", sizeof(struct record), 0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
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
    bdev_handle = bdev_open_by_path(mount_path, FMODE_READ | FMODE_WRITE, NULL, NULL);
    if (IS_ERR(bdev_handle)) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to open block device, error %ld\n", PTR_ERR(bdev_handle));
        ret = PTR_ERR(bdev_handle);
        goto error_free_rwsem;
    }
    bdev = bdev_handle->bdev;
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

    flush_wq = alloc_workqueue("hpkv_flush", WQ_UNBOUND | WQ_HIGHPRI, 4);
    if (!flush_wq) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to create flush workqueue\n");
        ret = -ENOMEM;
        goto error_put_device;
    }

    INIT_WORK(&hpkv_flush_work, flush_work_handler);

    // Start the write buffer thread after initializing flush_wq
    write_buffer_thread = kthread_run(write_buffer_worker, NULL, "hpkv_write_buffer");
    if (IS_ERR(write_buffer_thread)) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to create write buffer thread\n");
        ret = PTR_ERR(write_buffer_thread);
        goto error_destroy_flush_wq;
    }
    
    // Initialize the allocated_sectors bitmap
    bitmap_zero(allocated_sectors, SECTORS_BITMAP_SIZE);
    set_bit(0, allocated_sectors);  // Mark metadata sector as allocated
    smp_mb();  // Memory barrier after bit operations

    // Quick metadata check
    percpu_down_read(&rw_sem);
    ret = check_metadata(&metadata);
    percpu_up_read(&rw_sem);
    if (ret == 0) {
        if (metadata.total_records == 0 && metadata.total_size == 0 && !force_read_disk) {
            hpkv_log(HPKV_LOG_INFO, "Device is initialized but empty. Skipping full index load.\n");
            // Ensure in-memory structures reflect empty state
            atomic_set(&record_count, 0);
            atomic_long_set(&total_disk_usage, 0);
        } else if (force_initialize) {
            hpkv_log(HPKV_LOG_INFO, "Forcing initialization as empty device\n");
            ret = initialize_empty_device();
            if (ret < 0) {
                hpkv_log(HPKV_LOG_ERR, "Failed to initialize device\n");
                goto error_stop_thread;
            }
            // Ensure in-memory structures reflect empty state
            atomic_set(&record_count, 0);
            atomic_long_set(&total_disk_usage, 0);
        } else {
            hpkv_log(HPKV_LOG_INFO, "Device contains data. Loading indexes.\n");
            ret = load_indexes();
            if (ret == -EUCLEAN) {
                hpkv_log(HPKV_LOG_WARNING, "Device requires cleaning or repair. Consider running a repair operation.\n");
                // For now, we'll continue loading but with a warning
                // TODO: Trigger a repair operation here
            } else if (ret < 0) {
                hpkv_log(HPKV_LOG_ERR, "Failed to load indexes\n");
                goto error_stop_thread;
            }
        }
    } else if (ret == -EINVAL) {
        if (initialize_if_empty || force_initialize) {
            if (is_disk_empty(bdev) || force_initialize) {
                hpkv_log(HPKV_LOG_INFO, "Device is empty or force_initialize is set. Initializing for HPKV use.\n");
                ret = initialize_empty_device();
                if (ret < 0) {
                    hpkv_log(HPKV_LOG_ERR, "Failed to initialize device\n");
                    goto error_stop_thread;
                }
                // Ensure in-memory structures reflect empty state
                atomic_set(&record_count, 0);
                atomic_long_set(&total_disk_usage, 0);
            } else {
                hpkv_log(HPKV_LOG_ERR, "Device contains data but is not HPKV formatted. Refusing to initialize.\n");
                ret = -ENOTEMPTY;
                goto error_stop_thread;
            }
        } else {
            hpkv_log(HPKV_LOG_ERR, "Device is not formatted for HPKV use and initialize_if_empty is not set\n");
            ret = -ENODEV;
            goto error_stop_thread;
        }
    } else {
        hpkv_log(HPKV_LOG_ERR, "Failed to read metadata\n");
        goto error_stop_thread;
    }

    hpkv_log(HPKV_LOG_INFO, "Creating proc entry\n");
    proc_create(PROC_ENTRY, 0, NULL, &hpkv_proc_fops);
    hpkv_log(HPKV_LOG_INFO, "Proc entry created successfully\n");

    compact_wq = create_singlethread_workqueue("hpkv_compact");
    if (!compact_wq) {
        hpkv_log(HPKV_LOG_ALERT, "Failed to create compaction workqueue\n");
        ret = -ENOMEM;
        goto error_remove_proc;
    }

    INIT_DELAYED_WORK(&compact_work, compact_work_handler);
    //queue_delayed_work(compact_wq, &compact_work, COMPACT_INTERVAL);

    init_completion(&flush_completion);

    queue_delayed_work(system_wq, &cache_adjust_work, CACHE_ADJUST_INTERVAL);

    hpkv_log(HPKV_LOG_INFO, "Module loaded successfully\n");
    hpkv_log(HPKV_LOG_WARNING, "Registered with major number %d\n", major_num);
    return 0;

error_remove_proc:
    remove_proc_entry(PROC_ENTRY, NULL);
error_stop_thread:
    kthread_stop(write_buffer_thread);
error_destroy_flush_wq:
    destroy_workqueue(flush_wq);
error_put_device:
    bdev_release(bdev_handle);
error_free_rwsem:
    percpu_free_rwsem(&rw_sem);
error_destroy_cache:
    kmem_cache_destroy(record_cache);
error_unregister_chrdev:
    unregister_chrdev(major_num, DEVICE_NAME);

    hpkv_log(HPKV_LOG_ALERT, "Module initialization failed with error %d\n", ret);
    return ret;
}

static void __exit hpkv_exit(void)
{
    struct record *record;
    struct hlist_node *tmp;
    int bkt;
    struct cached_record *cached;
    struct write_buffer_entry *wb_entry, *wb_tmp;
    int retry_count = 0;
    const int max_retries = 10;

    hpkv_log(HPKV_LOG_INFO, "Starting module unload\n");

    // Cancel all pending work
    cancel_delayed_work_sync(&compact_work);
    cancel_work_sync(&hpkv_flush_work);

    // Stop the write buffer thread
    if (write_buffer_thread) {
        write_buffer_exit = true;
        wake_up(&write_buffer_wait);
        kthread_stop(write_buffer_thread);
        write_buffer_thread = NULL;
    }

    // Wait for compact_in_progress and flush_running
    while (atomic_read(&compact_in_progress) || atomic_read(&flush_running)) {
        if (retry_count++ >= max_retries) {
            hpkv_log(HPKV_LOG_ERR, "Timed out waiting for operations to complete. Forcing exit.\n");
            atomic_set(&compact_in_progress, 0);
            atomic_set(&flush_running, 0);
            break;
        }
        hpkv_log(HPKV_LOG_WARNING, "Waiting for ongoing operations to complete before unloading...\n");
        msleep(2000);  // Wait for 2 seconds before retrying
    }

    // Flush remaining entries in the write buffer
    flush_write_buffer();

    // Flush and destroy workqueues
    if (compact_wq) {
        flush_workqueue(compact_wq);
        destroy_workqueue(compact_wq);
        compact_wq = NULL;
    }
    if (flush_wq) {
        flush_workqueue(flush_wq);
        destroy_workqueue(flush_wq);
        flush_wq = NULL;
    }

    // Acquire write lock to prevent any concurrent access
    percpu_down_write(&rw_sem);

    // Clean up any remaining entries in the write buffer
    spin_lock(&write_buffer_lock);
    list_for_each_entry_safe(wb_entry, wb_tmp, &write_buffer, list) {
        list_del(&wb_entry->list);
        if (wb_entry->record) {
            if (wb_entry->record->value) {
                kfree(wb_entry->record->value);
                wb_entry->record->value = NULL;
            }
            kmem_cache_free(record_cache, wb_entry->record);
        }
        kfree(wb_entry);
    }
    spin_unlock(&write_buffer_lock);

    // Clear the hash table and schedule records for deletion
    hash_for_each_safe(kv_store, bkt, tmp, record, hash_node) {
        hash_del_rcu(&record->hash_node);
        rb_erase(&record->tree_node, &records_tree);
        call_rcu(&record->rcu, record_free_rcu);
    }

    // Ensure all RCU callbacks have completed
    rcu_barrier();

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
    atomic_set(&cache_count, 0);
    spin_unlock(&cache_lock);

    percpu_up_write(&rw_sem);

    // Close the block device
    if (bdev_handle) {
        sync_blockdev(bdev);
        bdev_release(bdev_handle);
        bdev_handle = NULL;
        bdev = NULL;
    }

    // Clean up other resources
    remove_proc_entry(PROC_ENTRY, NULL);
    
    // Wait for a short period to ensure all operations are complete
    msleep(500);

    if (record_cache) {
        kmem_cache_shrink(record_cache);
        kmem_cache_destroy(record_cache);
        record_cache = NULL;
    }

    unregister_chrdev(major_num, DEVICE_NAME);
    percpu_free_rwsem(&rw_sem);
   
    cancel_delayed_work_sync(&cache_adjust_work);

    hpkv_log(HPKV_LOG_INFO, "Module unloaded successfully\n");
}

module_init(hpkv_init);
module_exit(hpkv_exit);