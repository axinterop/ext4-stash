/**
 * ext4_stash.c
 * Fixed & Robust Block Slack Hider for Kernel 6.x
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MODULE_NAME "ext4_stash"
#define PROC_DIR "ext4_stash"
#define PROC_HIDE "hide"
#define PROC_UNHIDE "unhide"
#define MAX_MSG_SIZE 255

MODULE_LICENSE("GPL");
MODULE_AUTHOR("201295");

// Global state for unhide
static char unhide_path_store[PATH_MAX];
static u64 unhide_phys_block = 0;
static int unhide_offset = 0;
static DEFINE_MUTEX(stash_mutex);

// --- Helper: Low-Level Block Access ---
static int raw_block_access(struct super_block *sb, u64 phys_block, int offset, char *data, int data_len, bool do_write) {
    struct buffer_head *bh;
    int ret = 0;
    int slack_avail;

    if (!sb) return -EINVAL;

    // Read the raw physical block from the device
    bh = sb_bread(sb, phys_block);
    if (!bh) {
        pr_err("[%s] I/O Error: Cannot read physical block %llu\n", MODULE_NAME, phys_block);
        return -EIO;
    }

    slack_avail = sb->s_blocksize - offset;

    lock_buffer(bh);
    unsigned char *ptr = (unsigned char *)bh->b_data;

    if (do_write) {
        // [Len][Data]
        if (data_len + 1 > slack_avail) {
            unlock_buffer(bh);
            brelse(bh);
            return -EINVAL;
        }
        ptr[offset] = (unsigned char)data_len;
        memcpy(ptr + offset + 1, data, data_len);

        mark_buffer_dirty(bh);

    } else {
        // Read
        int stored_len = ptr[offset];
        if (stored_len < 0) stored_len = 0;
        if (stored_len > MAX_MSG_SIZE) stored_len = MAX_MSG_SIZE;
        if (stored_len > slack_avail - 1) stored_len = slack_avail - 1;

        if (stored_len > 0) {
            if (data_len < stored_len) stored_len = data_len;
            memcpy(data, ptr + offset + 1, stored_len);
            ret = stored_len;
        }
    }

    unlock_buffer(bh);

    if (do_write) {
        ret = sync_dirty_buffer(bh);
        if (ret == 0) {
            pr_info("[%s] Hidden %d bytes in phys block %llu\n", MODULE_NAME, data_len, phys_block);
        }
    }

    brelse(bh);
    return ret;
}

// --- Proc: Hide ---
static ssize_t hide_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char *kbuf, *p;
    char *path_s, *phys_s, *off_s, *data_s;
    u64 phys_block;
    int offset;
    struct file *filp;
    int ret;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    // SAFE COPY: Ensures null-termination and prevents boundary bugs
    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    // SAFE PARSING: Use strsep to tokenize
    p = kbuf;
    path_s = strsep(&p, "\n");
    phys_s = strsep(&p, "\n");
    off_s  = strsep(&p, "\n");
    data_s = strsep(&p, "\n");


    if (!path_s || !phys_s || !off_s || !data_s) {
        kfree(kbuf);
        return -EINVAL; // Malformed input
    }

    if (kstrtoull(phys_s, 10, &phys_block) || kstrtouint(off_s, 10, &offset)) {
        kfree(kbuf);
        return -EINVAL;
    }

    // pr_info("[%s] %s %d %d %s\n", MODULE_NAME, path_s, phys_block, offset, data_s);


    // We open the file just to get the Superblock reference
    filp = filp_open(path_s, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        kfree(kbuf);
        return PTR_ERR(filp);
    }

    pr_info("[%s] filp_open was successful.\n", MODULE_NAME);

    //
    mutex_lock(&stash_mutex);
    ret = raw_block_access(file_inode(filp)->i_sb, phys_block, offset, data_s, strlen(data_s), true);
    mutex_unlock(&stash_mutex);
    //
    filp_close(filp, NULL);
    kfree(kbuf);
    return (ret < 0) ? ret : count;
}

static const struct proc_ops hide_ops = { .proc_write = hide_write };

// --- Proc: Unhide ---
static ssize_t unhide_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char *kbuf, *p;
    char *path_s, *phys_s, *off_s;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    p = kbuf;
    path_s = strsep(&p, "\n");
    phys_s = strsep(&p, "\n");
    off_s  = strsep(&p, "\n");

    if (path_s && phys_s && off_s) {
        mutex_lock(&stash_mutex);
        strscpy(unhide_path_store, path_s, PATH_MAX);
        kstrtoull(phys_s, 10, &unhide_phys_block);
        kstrtouint(off_s, 10, &unhide_offset);
        mutex_unlock(&stash_mutex);
    }

    kfree(kbuf);
    return count;
}

static ssize_t unhide_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    char *data_buf;
    struct file *filp;
    int ret;

    if (*ppos > 0) return 0; // EOF

    data_buf = kzalloc(MAX_MSG_SIZE + 1, GFP_KERNEL);
    if (!data_buf) return -ENOMEM;

    mutex_lock(&stash_mutex);

    // Re-open to ensure we have a valid SB reference
    filp = filp_open(unhide_path_store, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        mutex_unlock(&stash_mutex);
        kfree(data_buf);
        return -EINVAL;
    }

    ret = raw_block_access(file_inode(filp)->i_sb, unhide_phys_block, unhide_offset, data_buf, MAX_MSG_SIZE, false);

    filp_close(filp, NULL);
    mutex_unlock(&stash_mutex);

    if (ret < 0) {
        kfree(data_buf);
        return ret;
    }

    data_buf[ret] = '\n';
    ret++;

    if (copy_to_user(ubuf, data_buf, ret)) {
        ret = -EFAULT;
    } else {
        *ppos += ret;
    }

    kfree(data_buf);
    return ret;
}

static const struct proc_ops unhide_ops = { .proc_write = unhide_write, .proc_read = unhide_read };

// --- Init/Exit ---
static struct proc_dir_entry *proc_dir;
static int __init stash_init(void) {
    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) return -ENOMEM;
    proc_create(PROC_HIDE, 0666, proc_dir, &hide_ops);
    proc_create(PROC_UNHIDE, 0666, proc_dir, &unhide_ops);
    pr_info("[%s] Loaded successfully.\n", MODULE_NAME);
    return 0;
}
static void __exit stash_exit(void) {
    remove_proc_entry(PROC_HIDE, proc_dir);
    remove_proc_entry(PROC_UNHIDE, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);
    pr_info("[%s] Unloaded.\n", MODULE_NAME);
}
module_init(stash_init);
module_exit(stash_exit);
