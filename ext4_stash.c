/**
 * ext4_stash.c
 * Kernel Module for hiding data in filesystem block slack space.
 * Target Kernel: 6.x (tested logic for 6.1+)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MODULE_NAME "ext4_stash"
#define PROC_DIR "ext4_stash"
#define PROC_HIDE "hide"
#define PROC_UNHIDE "unhide"
#define MAX_MSG_SIZE 255

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gemini");
MODULE_DESCRIPTION("Hides data in ext4 block slack space");
MODULE_VERSION("1.0");

// Global state for the unhide target path
static char unhide_target_path[PATH_MAX];
static DEFINE_MUTEX(stash_mutex); // Simple lock for global buffer safety

// --- Helper: Open File ---
static struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = NULL;
    filp = filp_open(path, flags, rights);
    return filp;
}

// --- Helper: Close File ---
static void file_close(struct file *file) {
    if (file && !IS_ERR(file))
        filp_close(file, NULL);
}

/**
 * Core Logic: Map Logical Block -> Physical Block -> Modify Slack
 * * 1. Calculate the last block of the file.
 * 2. Read the page containing that block.
 * 3. Walk buffer_heads to find the physical disk block.
 * 4. Read/Write the slack space directly on the buffer head.
 */
static int manipulate_slack_space(const char *filepath, char *data, int data_len, bool do_write) {
    struct file *filp;
    struct inode *inode;
    struct page *page;
    struct buffer_head *bh, *head;
    loff_t file_size;
    unsigned long block_size;
    pgoff_t index;
    int offset_in_block;
    int slack_space_avail;
    int ret = 0;

    filp = file_open(filepath, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("[%s] Error opening file: %s\n", MODULE_NAME, filepath);
        return PTR_ERR(filp);
    }

    inode = file_inode(filp);
    file_size = i_size_read(inode);
    block_size = inode->i_sb->s_blocksize;

    // Calculate offset in the block
    offset_in_block = file_size & (block_size - 1);

    // pr_warn("[%s] file_size: %d", MODULE_NAME, file_size);
    // pr_warn("[%s] block_size: %d", MODULE_NAME, block_size);
    // pr_warn("[%s] offset_in_block: %d", MODULE_NAME, offset_in_block);


    // If offset is 0, the file ends exactly at block boundary. No slack space.
    if (offset_in_block == 0) {
        pr_warn("[%s] No slack space available (file aligns with block size).\n", MODULE_NAME);
        file_close(filp);
        return -ENOSPC; // No space left on device context
    }

    slack_space_avail = block_size - offset_in_block;

    // Check size constraints
    if (do_write) {
        // We need 1 byte for length + data
        if ((1 + data_len) > slack_space_avail) {
            pr_err("[%s] Message too long for available slack space (%d bytes).\n", MODULE_NAME, slack_space_avail);
            file_close(filp);
            return -EINVAL;
        }
    }

    // Read the page containing the end of the file
    index = file_size >> PAGE_SHIFT;
    page = read_mapping_page(inode->i_mapping, index, NULL);
    if (IS_ERR(page)) {
        file_close(filp);
        return PTR_ERR(page);
    }

    struct folio *folio = page_folio(page);

    // In modern kernels, we need to ensure buffer_heads are attached to get physical mapping
    if (!folio_buffers(folio))
        create_empty_buffers(folio, block_size, 0);

    head = folio_buffers(folio);
    bh = head;

    // Walk buffers to find the specific block corresponding to the file end
    // (A page might contain multiple blocks, e.g., 4k page, 1k blocks)
    // We calculated offset_in_block relative to the specific block,
    // but we need the correct buffer_head within the page.
    // However, usually block_size == page_size (4k) on x86, so often only 1 bh.
    // For correctness, we walk.

    // Calculate which block in the page we are targeting
    int block_in_page = (file_size >> inode->i_blkbits) & ((PAGE_SIZE / block_size) - 1);
    int i;
    for (i = 0; i < block_in_page; i++) {
        bh = bh->b_this_page;
    }

    // Ensure the buffer is mapped to disk
    if (!buffer_mapped(bh)) {
        // If it's not mapped, the FS hasn't assigned a physical block yet?
        // For an existing file end, it should be mapped.
        pr_err("[%s] Buffer not mapped. Cannot find physical block.\n", MODULE_NAME);
        put_page(page);
        file_close(filp);
        return -EIO;
    }

    // NOW we have the physical buffer.
    // To be absolutely sure we are bypassing cache effects for the *slack* (which fs might ignore),
    // we can use sb_bread to read it as a raw disk block, OR simply modify this bh
    // and force a sync. We will modify this bh.

    lock_buffer(bh);

    unsigned char *ptr = (unsigned char *)bh->b_data;

    if (do_write) {
        // WRITE OPERATION
        // Format: [Length Byte][Data...]
        ptr[offset_in_block] = (unsigned char)data_len;
        memcpy(ptr + offset_in_block + 1, data, data_len);

        mark_buffer_dirty(bh);
        // Force synchronous write to disk to survive unmount
        ret = sync_dirty_buffer(bh);
        if (ret == 0) {
            pr_info("[%s] Data hidden in block %llu at offset %d.\n",
                    MODULE_NAME, (unsigned long long)bh->b_blocknr, offset_in_block);
        }
    } else {
        // READ OPERATION
        int stored_len = ptr[offset_in_block];
        if (stored_len > MAX_MSG_SIZE || stored_len <= 0) {
            // Either no data hidden (garbage) or invalid length
            // We'll treat garbage as "empty" or copy what we find if reasonable.
            // For safety, let's clamp.
            if (stored_len < 0) stored_len = 0;
            // If it looks like garbage, we just return empty string in this simple PoC
            // But let's try to read it anyway if it's within bounds.
            if (stored_len > slack_space_avail - 1) stored_len = slack_space_avail - 1;
        }

        if (stored_len > 0) {
            // Copy out to the provided buffer
            if (data_len < stored_len) stored_len = data_len; // buffer safety
            memcpy(data, ptr + offset_in_block + 1, stored_len);
            ret = stored_len; // Return bytes read
        } else {
            ret = 0;
        }
    }

    unlock_buffer(bh);
    put_page(page);
    file_close(filp);
    return ret;
}

// --- Proc File: /proc/ext4_stash/hide ---

static ssize_t hide_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char *kbuf;
    char *filepath;
    char *message;
    int ret;

    if (count > PAGE_SIZE) return -EINVAL;

    kbuf = kzalloc(count + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, ubuf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }
    kbuf[count] = '\0';

    // Remove potential trailing newline
    if (kbuf[count-1] == '\n') kbuf[count-1] = '\0';

    // Format: "filepath\nmessage"
    filepath = kbuf;
    message = strchr(kbuf, '\n');

    if (!message) {
        pr_err("[%s] Invalid format. Expected 'filepath\\nmessage'\n", MODULE_NAME);
        kfree(kbuf);
        return -EINVAL;
    }

    *message = '\0'; // Terminate filepath
    message++;       // Point to data

    if (strlen(message) > MAX_MSG_SIZE) {
        pr_err("[%s] Message too long (max %d)\n", MODULE_NAME, MAX_MSG_SIZE);
        kfree(kbuf);
        return -EINVAL;
    }

    mutex_lock(&stash_mutex);
    ret = manipulate_slack_space(filepath, message, strlen(message), true);
    mutex_unlock(&stash_mutex);

    kfree(kbuf);
    return (ret < 0) ? ret : count;
}

static const struct proc_ops hide_ops = {
    .proc_write = hide_write,
};

// --- Proc File: /proc/ext4_stash/unhide ---

static ssize_t unhide_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    // User writes the filepath here to prepare for reading
    if (count >= PATH_MAX) return -EINVAL;

    mutex_lock(&stash_mutex);
    if (copy_from_user(unhide_target_path, ubuf, count)) {
        mutex_unlock(&stash_mutex);
        return -EFAULT;
    }
    unhide_target_path[count] = '\0';
    // Trim newline
    if (count > 0 && unhide_target_path[count-1] == '\n')
        unhide_target_path[count-1] = '\0';

    mutex_unlock(&stash_mutex);
    return count;
}

static ssize_t unhide_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    char *data_buf;
    int bytes_read;
    int ret;

    // Only allow one read pass (simple implementation)
    if (*ppos > 0) return 0;

    data_buf = kzalloc(MAX_MSG_SIZE + 1, GFP_KERNEL);
    if (!data_buf) return -ENOMEM;

    mutex_lock(&stash_mutex);
    if (strlen(unhide_target_path) == 0) {
        mutex_unlock(&stash_mutex);
        kfree(data_buf);
        return -EINVAL; // No path set
    }

    bytes_read = manipulate_slack_space(unhide_target_path, data_buf, MAX_MSG_SIZE, false);
    mutex_unlock(&stash_mutex);

    if (bytes_read < 0) {
        kfree(data_buf);
        return bytes_read; // Error code
    }

    // Add newline for display niceness
    data_buf[bytes_read] = '\n';
    bytes_read++;

    ret = bytes_read;
    if (copy_to_user(ubuf, data_buf, bytes_read)) {
        ret = -EFAULT;
    } else {
        *ppos += bytes_read;
    }

    kfree(data_buf);
    return ret;
}

static const struct proc_ops unhide_ops = {
    .proc_write = unhide_write,
    .proc_read  = unhide_read,
};

// --- Module Init/Exit ---

static struct proc_dir_entry *proc_dir;

static int __init stash_init(void) {
    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) return -ENOMEM;

    if (!proc_create(PROC_HIDE, 0666, proc_dir, &hide_ops)) {
        remove_proc_entry(PROC_DIR, NULL);
        return -ENOMEM;
    }

    if (!proc_create(PROC_UNHIDE, 0666, proc_dir, &unhide_ops)) {
        remove_proc_entry(PROC_HIDE, proc_dir);
        remove_proc_entry(PROC_DIR, NULL);
        return -ENOMEM;
    }

    pr_info("[%s] Module loaded. /proc/%s created.\n", MODULE_NAME, PROC_DIR);
    return 0;
}

static void __exit stash_exit(void) {
    remove_proc_entry(PROC_HIDE, proc_dir);
    remove_proc_entry(PROC_UNHIDE, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);
    pr_info("[%s] Module unloaded.\n", MODULE_NAME);
}

module_init(stash_init);
module_exit(stash_exit);
