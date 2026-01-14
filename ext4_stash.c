#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#define MODULE_NAME "ext4_stash"
#define PROC_DIR "ext4_stash"
#define PROC_HIDE "hide"
#define PROC_UNHIDE "unhide"
#define PROC_CLEAR "clear"
#define PROC_MAP "map"
#define MAX_MSG_CHUNK 4090  // 4096 - 6 header bytes

// Enhanced protocol: [Magic1][Magic2][Len_High][Len_Low][ChunkID_High][ChunkID_Low][Data]
#define MAGIC_BYTE_1 0x53  // 'S'
#define MAGIC_BYTE_2 0x54  // 'T'
#define HEADER_SIZE 6      // 2 magic + 2 length + 2 chunk ID

#define OP_READ 0
#define OP_WRITE 1
#define OP_CLEAR 2

MODULE_LICENSE("GPL");
MODULE_AUTHOR("201295");

static char *stash_map_path = "/root/.stash_map";
module_param(stash_map_path, charp, 0644);
MODULE_PARM_DESC(stash_map_path, "Path to persistent stash map file");

static DEFINE_MUTEX(stash_mutex);
static struct proc_dir_entry *proc_dir;

// Map structure: maps message_id -> list of chunk locations
struct stash_map_entry {
    struct list_head list;
    uint64_t msg_id;
    uint32_t total_chunks;
    uint64_t *chunks;  // Array of: phys_block << 32 | offset
};

static LIST_HEAD(stash_list);
static uint64_t next_msg_id = 1;

// Helper function to parse map file line
static int parse_map_line(char *line, uint64_t *msg_id, uint32_t *total_chunks, uint64_t *chunks, int max_chunks) {
    char *token;
    int i = 0;

    // Parse message ID
    token = strsep(&line, ":");
    if (!token || kstrtoull(token, 10, msg_id))
        return -EINVAL;

    // Parse total chunks
    token = strsep(&line, ":");
    if (!token || kstrtouint(token, 10, total_chunks))
        return -EINVAL;

    // Parse each chunk location
    for (i = 0; i < *total_chunks && i < max_chunks; i++) {
        token = strsep(&line, ":");
        if (!token || kstrtoull(token, 10, &chunks[i]))
            break;
    }

    return i;  // Return number of chunks parsed
}

// Read persistent map
static int read_persistent_map(void) {
    struct file *filp;
    loff_t pos = 0;
    ssize_t ret;
    char buffer[4096];
    char *line, *line_ptr;
    int line_num = 0;

    filp = filp_open(stash_map_path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_info("[%s] No existing map file found, starting fresh\n", MODULE_NAME);
        return 0;
    }

    ret = kernel_read(filp, buffer, sizeof(buffer) - 1, &pos);
    filp_close(filp, NULL);

    if (ret > 0) {
        buffer[ret] = '\0';
        pr_info("[%s] Loading persistent map (%zd bytes)\n", MODULE_NAME, ret);

        // Parse each line
        line = buffer;
        while ((line_ptr = strsep(&line, "\n")) != NULL && *line_ptr != '\0') {
            uint64_t msg_id;
            uint32_t total_chunks;
            uint64_t chunks[100];  // Max 100 chunks per message
            int chunks_parsed;

            line_num++;

            chunks_parsed = parse_map_line(line_ptr, &msg_id, &total_chunks, chunks, 100);
            if (chunks_parsed <= 0 || chunks_parsed != total_chunks) {
                pr_warn("[%s] Skipping invalid map line %d\n", MODULE_NAME, line_num);
                continue;
            }

            // Create map entry
            struct stash_map_entry *entry = kmalloc(
                sizeof(struct stash_map_entry) + total_chunks * sizeof(uint64_t),
                GFP_KERNEL
            );
            if (!entry) {
                pr_warn("[%s] Memory allocation failed for map entry\n", MODULE_NAME);
                continue;
            }

            entry->msg_id = msg_id;
            entry->total_chunks = total_chunks;
            entry->chunks = (uint64_t *)(entry + 1);
            memcpy(entry->chunks, chunks, total_chunks * sizeof(uint64_t));

            list_add_tail(&entry->list, &stash_list);

            if (msg_id >= next_msg_id)
                next_msg_id = msg_id + 1;

            pr_debug("[%s] Loaded message %llu with %u chunks\n",
                    MODULE_NAME, msg_id, total_chunks);
        }

        pr_info("[%s] Loaded %d messages from map\n", MODULE_NAME, line_num);
    }

    return 0;
}

// Write persistent map
static int write_persistent_map(void) {
    struct file *filp;
    loff_t pos = 0;
    ssize_t ret;
    char *buffer;
    size_t buf_size = 4096;
    size_t len = 0;
    struct stash_map_entry *entry;

    buffer = kmalloc(buf_size, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    mutex_lock(&stash_mutex);

    list_for_each_entry(entry, &stash_list, list) {
        // Format: msg_id:total_chunks:chunk1:chunk2:...
        int written = snprintf(buffer + len, buf_size - len,
                              "%llu:%u", entry->msg_id, entry->total_chunks);

        if (written < 0 || written >= buf_size - len) {
            // Buffer full, write what we have
            break;
        }
        len += written;

        for (int i = 0; i < entry->total_chunks && len < buf_size - 20; i++) {
            written = snprintf(buffer + len, buf_size - len,
                              ":%llu", entry->chunks[i]);
            if (written < 0 || written >= buf_size - len) {
                break;
            }
            len += written;
        }

        if (len < buf_size - 1) {
            buffer[len++] = '\n';
        }
    }

    mutex_unlock(&stash_mutex);

    // Write to file
    filp = filp_open(stash_map_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(filp)) {
        kfree(buffer);
        return PTR_ERR(filp);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ret = kernel_write(filp, buffer, len, &pos);
#else
    ret = kernel_write(filp, buffer, len, pos);
#endif

    filp_close(filp, NULL);
    kfree(buffer);

    if (ret < 0) {
        pr_err("[%s] Failed to write map: %ld\n", MODULE_NAME, ret);
        return ret;
    }

    pr_info("[%s] Wrote persistent map (%ld bytes)\n", MODULE_NAME, ret);
    return 0;
}

// Block access with enhanced 16-bit length protocol
static int raw_block_access(struct super_block *sb, uint64_t phys_block,
                           int offset, char *data, int data_len,
                           uint16_t chunk_id, int mode) {
    struct buffer_head *bh;
    int ret = 0;
    int slack_avail;
    uint16_t stored_len, stored_chunk_id;

    if (!sb) return -EINVAL;

    bh = sb_bread(sb, phys_block);
    if (!bh) {
        pr_err("[%s] I/O Error: Cannot read physical block %llu\n",
               MODULE_NAME, phys_block);
        return -EIO;
    }

    slack_avail = sb->s_blocksize - offset;

    lock_buffer(bh);
    {
        unsigned char *ptr = (unsigned char *)bh->b_data;

        if (mode == OP_WRITE) {
            // Protocol: [Magic1][Magic2][Len_High][Len_Low][ChunkID_High][ChunkID_Low][Data]
            if (data_len + HEADER_SIZE > slack_avail) {
                ret = -EINVAL;
                pr_err("[%s] Not enough slack space: need %d, have %d\n",
                       MODULE_NAME, data_len + HEADER_SIZE, slack_avail);
                goto out_unlock;
            }

            // Write header
            ptr[offset]     = MAGIC_BYTE_1;
            ptr[offset + 1] = MAGIC_BYTE_2;
            ptr[offset + 2] = (data_len >> 8) & 0xFF;   // Length high byte
            ptr[offset + 3] = data_len & 0xFF;          // Length low byte
            ptr[offset + 4] = (chunk_id >> 8) & 0xFF;   // Chunk ID high byte
            ptr[offset + 5] = chunk_id & 0xFF;          // Chunk ID low byte

            // Write data
            memcpy(ptr + offset + HEADER_SIZE, data, data_len);
            mark_buffer_dirty(bh);

            pr_debug("[%s] Wrote chunk %d (%d bytes) to block %llu offset %d\n",
                    MODULE_NAME, chunk_id, data_len, phys_block, offset);

        } else if (mode == OP_CLEAR) {
            // Clear the entire slack space
            memset(ptr + offset, 0, slack_avail);
            mark_buffer_dirty(bh);
            pr_debug("[%s] Cleared block %llu offset %d\n",
                    MODULE_NAME, phys_block, offset);

        } else {  // OP_READ
            // Verify magic bytes
            if (ptr[offset] != MAGIC_BYTE_1 || ptr[offset + 1] != MAGIC_BYTE_2) {
                ret = -ENODATA;
                pr_debug("[%s] No magic bytes at block %llu offset %d\n",
                        MODULE_NAME, phys_block, offset);
                goto out_unlock;
            }

            // Read header
            stored_len = (ptr[offset + 2] << 8) | ptr[offset + 3];
            stored_chunk_id = (ptr[offset + 4] << 8) | ptr[offset + 5];

            if (stored_len > slack_avail - HEADER_SIZE) {
                stored_len = slack_avail - HEADER_SIZE;
            }

            if (stored_len > 0) {
                if (data_len < stored_len) stored_len = data_len;
                memcpy(data, ptr + offset + HEADER_SIZE, stored_len);
                ret = stored_len;

                pr_debug("[%s] Read chunk %d (%d bytes) from block %llu offset %d\n",
                        MODULE_NAME, stored_chunk_id, stored_len, phys_block, offset);
            } else {
                ret = -ENODATA;
            }
        }
    }
out_unlock:
    unlock_buffer(bh);

    if (mode == OP_WRITE || mode == OP_CLEAR) {
        if (buffer_dirty(bh)) {
            sync_dirty_buffer(bh);
        }
        pr_info("[%s] %s block %llu offset %d\n", MODULE_NAME,
               mode == OP_CLEAR ? "Cleared" : "Wrote to",
               phys_block, offset);
    }

    brelse(bh);
    return ret;
}

// Hide operation - accepts chunked data
static ssize_t hide_write(struct file *file, const char __user *ubuf,
                         size_t count, loff_t *ppos) {
    char *kbuf, *p;
    char *msg_id_s, *chunk_idx_s, *total_chunks_s;
    char *path_s, *phys_s, *off_s, *data_s;
    uint64_t msg_id, phys_block;
    int chunk_idx, total_chunks, offset;
    struct file *filp;
    int ret;
    size_t data_len;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    p = kbuf;
    msg_id_s = strsep(&p, "\n");
    chunk_idx_s = strsep(&p, "\n");
    total_chunks_s = strsep(&p, "\n");
    path_s = strsep(&p, "\n");
    phys_s = strsep(&p, "\n");
    off_s = strsep(&p, "\n");
    data_s = p;  // Rest is binary data

    if (!msg_id_s || !chunk_idx_s || !total_chunks_s ||
        !path_s || !phys_s || !off_s || !data_s) {
        kfree(kbuf);
        return -EINVAL;
    }

    // Calculate actual data length (binary safe)
    data_len = count - (data_s - kbuf);

    if (kstrtoull(msg_id_s, 10, &msg_id) ||
        kstrtoint(chunk_idx_s, 10, &chunk_idx) ||
        kstrtoint(total_chunks_s, 10, &total_chunks) ||
        kstrtoull(phys_s, 10, &phys_block) ||
        kstrtoint(off_s, 10, &offset)) {
        kfree(kbuf);
        return -EINVAL;
    }

    // Validate indices
    if (chunk_idx < 0 || chunk_idx >= total_chunks || total_chunks <= 0) {
        kfree(kbuf);
        return -EINVAL;
    }

    filp = filp_open(path_s, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        kfree(kbuf);
        return PTR_ERR(filp);
    }

    mutex_lock(&stash_mutex);

    // Find or create map entry
    struct stash_map_entry *entry = NULL;
    list_for_each_entry(entry, &stash_list, list) {
        if (entry->msg_id == msg_id) break;
    }

    if (&entry->list == &stash_list) {  // Not found, create new entry
        entry = kmalloc(sizeof(struct stash_map_entry) +
                       total_chunks * sizeof(uint64_t), GFP_KERNEL);
        if (!entry) {
            mutex_unlock(&stash_mutex);
            filp_close(filp, NULL);
            kfree(kbuf);
            return -ENOMEM;
        }
        entry->msg_id = msg_id;
        entry->total_chunks = total_chunks;
        entry->chunks = (uint64_t *)(entry + 1);
        memset(entry->chunks, 0, total_chunks * sizeof(uint64_t));
        list_add_tail(&entry->list, &stash_list);

        // Update next_msg_id if needed
        if (msg_id >= next_msg_id) next_msg_id = msg_id + 1;
    }

    // Validate total_chunks matches
    if (entry->total_chunks != total_chunks) {
        mutex_unlock(&stash_mutex);
        filp_close(filp, NULL);
        kfree(kbuf);
        return -EINVAL;
    }

    // Store this chunk's location
    entry->chunks[chunk_idx] = (phys_block << 32) | (offset & 0xFFFFFFFF);

    // Write data to block
    ret = raw_block_access(file_inode(filp)->i_sb, phys_block, offset,
                          data_s, data_len, chunk_idx, OP_WRITE);

    mutex_unlock(&stash_mutex);

    filp_close(filp, NULL);
    kfree(kbuf);

    if (ret < 0) return ret;

    // Update persistent map when last chunk is written
    if (chunk_idx == total_chunks - 1) {
        write_persistent_map();
    }

    return count;
}

static const struct proc_ops hide_ops = { .proc_write = hide_write };

// Unhide operation - reconstructs data from chunks
static ssize_t unhide_write(struct file *file, const char __user *ubuf,
                          size_t count, loff_t *ppos) {
    char *kbuf;
    uint64_t msg_id;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    if (kstrtoull(kbuf, 10, &msg_id)) {
        kfree(kbuf);
        return -EINVAL;
    }

    // Store msg_id in file private data for read operation
    file->private_data = (void *)(unsigned long)msg_id;

    kfree(kbuf);
    return count;
}

static ssize_t unhide_read(struct file *file, char __user *ubuf,
                         size_t count, loff_t *ppos) {
    uint64_t msg_id = (uint64_t)(unsigned long)file->private_data;
    struct stash_map_entry *entry = NULL;
    char *data_buf;
    size_t total_copied = 0;
    int ret;

    if (*ppos > 0 || msg_id == 0) return 0;

    mutex_lock(&stash_mutex);

    // Find the message
    list_for_each_entry(entry, &stash_list, list) {
        if (entry->msg_id == msg_id) break;
    }

    if (&entry->list == &stash_list) {
        mutex_unlock(&stash_mutex);
        return -ENOENT;
    }

    // Allocate buffer for reconstructed data
    data_buf = kzalloc(entry->total_chunks * MAX_MSG_CHUNK, GFP_KERNEL);
    if (!data_buf) {
        mutex_unlock(&stash_mutex);
        return -ENOMEM;
    }

    // Reconstruct from all chunks in order
    for (int chunk_idx = 0; chunk_idx < entry->total_chunks; chunk_idx++) {
        uint64_t chunk_info = entry->chunks[chunk_idx];
        if (chunk_info == 0) {
            pr_warn("[%s] Missing chunk %d for message %llu\n",
                   MODULE_NAME, chunk_idx, msg_id);
            continue;
        }

        uint64_t phys_block = chunk_info >> 32;
        int offset = chunk_info & 0xFFFFFFFF;

        // We need a superblock to read the data. We'll use the root filesystem.
        // In a real implementation, we should store and use the carrier path.
        struct file *filp = filp_open("/", O_RDONLY, 0);
        if (IS_ERR(filp)) {
            pr_err("[%s] Failed to open root for superblock\n", MODULE_NAME);
            continue;
        }

        char chunk_buf[MAX_MSG_CHUNK];
        ret = raw_block_access(file_inode(filp)->i_sb, phys_block, offset,
                              chunk_buf, MAX_MSG_CHUNK, 0, OP_READ);

        filp_close(filp, NULL);

        if (ret > 0) {
            if (total_copied + ret <= entry->total_chunks * MAX_MSG_CHUNK) {
                memcpy(data_buf + total_copied, chunk_buf, ret);
                total_copied += ret;
                pr_debug("[%s] Recovered chunk %d: %d bytes\n",
                        MODULE_NAME, chunk_idx, ret);
            }
        } else {
            pr_warn("[%s] Failed to read chunk %d: %d\n",
                   MODULE_NAME, chunk_idx, ret);
        }
    }

    mutex_unlock(&stash_mutex);

    // Copy to userspace
    if (total_copied > 0) {
        size_t to_copy = min((size_t)count, total_copied);
        if (copy_to_user(ubuf, data_buf, to_copy)) {
            kfree(data_buf);
            return -EFAULT;
        }
        *ppos += to_copy;
        kfree(data_buf);
        return to_copy;
    }

    kfree(data_buf);
    return -ENODATA;
}

static const struct proc_ops unhide_ops = {
    .proc_write = unhide_write,
    .proc_read = unhide_read
};

// Clear operation - removes all chunks of a message
static ssize_t clear_write(struct file *file, const char __user *ubuf,
                          size_t count, loff_t *ppos) {
    char *kbuf;
    uint64_t msg_id;
    struct stash_map_entry *entry, *tmp;
    int found = 0;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    if (kstrtoull(kbuf, 10, &msg_id)) {
        kfree(kbuf);
        return -EINVAL;
    }

    mutex_lock(&stash_mutex);

    // Find and remove the message
    list_for_each_entry_safe(entry, tmp, &stash_list, list) {
        if (entry->msg_id == msg_id) {
            list_del(&entry->list);
            kfree(entry);
            found = 1;
            break;
        }
    }

    mutex_unlock(&stash_mutex);
    kfree(kbuf);

    if (found) {
        // Update persistent map
        write_persistent_map();
        pr_info("[%s] Cleared message %llu\n", MODULE_NAME, msg_id);
        return count;
    } else {
        return -ENOENT;
    }
}

static const struct proc_ops clear_ops = { .proc_write = clear_write };

// Map proc entry to view current stashes
static int map_show(struct seq_file *m, void *v) {
    struct stash_map_entry *entry;

    mutex_lock(&stash_mutex);

    seq_printf(m, "Stash Map (stored in %s)\n", stash_map_path);
    seq_printf(m, "================================\n");

    if (list_empty(&stash_list)) {
        seq_puts(m, "No hidden messages\n");
    } else {
        list_for_each_entry(entry, &stash_list, list) {
            seq_printf(m, "Message ID: %llu\n", entry->msg_id);
            seq_printf(m, "  Chunks: %u\n", entry->total_chunks);
            seq_printf(m, "  Locations:\n");

            for (int i = 0; i < entry->total_chunks && i < 5; i++) {
                if (entry->chunks[i] != 0) {
                    uint64_t phys_block = entry->chunks[i] >> 32;
                    int offset = entry->chunks[i] & 0xFFFFFFFF;
                    seq_printf(m, "    [%d] Block: %llu, Offset: %d\n",
                              i, phys_block, offset);
                } else {
                    seq_printf(m, "    [%d] <missing>\n", i);
                }
            }

            if (entry->total_chunks > 5) {
                seq_printf(m, "    ... and %d more chunks\n",
                          entry->total_chunks - 5);
            }
            seq_putc(m, '\n');
        }
    }

    seq_printf(m, "Next message ID: %llu\n", next_msg_id);
    mutex_unlock(&stash_mutex);
    return 0;
}

static int map_open(struct inode *inode, struct file *file) {
    return single_open(file, map_show, NULL);
}

static const struct proc_ops map_ops = {
    .proc_open = map_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init stash_init(void) {
    int ret;

    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) return -ENOMEM;

    proc_create(PROC_HIDE, 0666, proc_dir, &hide_ops);
    proc_create(PROC_UNHIDE, 0666, proc_dir, &unhide_ops);
    proc_create(PROC_CLEAR, 0666, proc_dir, &clear_ops);
    proc_create(PROC_MAP, 0444, proc_dir, &map_ops);

    // Load persistent map
    ret = read_persistent_map();
    if (ret) {
        pr_warn("[%s] Failed to load persistent map: %d\n", MODULE_NAME, ret);
    }

    pr_info("[%s] Loaded successfully (chunking support)\n", MODULE_NAME);
    return 0;
}

static void __exit stash_exit(void) {
    // Save persistent map
    write_persistent_map();

    // Clean up in-memory entries
    struct stash_map_entry *entry, *tmp;
    mutex_lock(&stash_mutex);
    list_for_each_entry_safe(entry, tmp, &stash_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&stash_mutex);

    remove_proc_entry(PROC_HIDE, proc_dir);
    remove_proc_entry(PROC_UNHIDE, proc_dir);
    remove_proc_entry(PROC_CLEAR, proc_dir);
    remove_proc_entry(PROC_MAP, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);

    pr_info("[%s] Unloaded\n", MODULE_NAME);
}

module_init(stash_init);
module_exit(stash_exit);
