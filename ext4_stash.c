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
#define PROC_CLEAR "clear"
#define MAX_MSG_SIZE 255

#define OP_READ 0
#define OP_WRITE 1
#define OP_CLEAR 2

#define MAGIC_BYTE_1 0x53  // 'S'
#define MAGIC_BYTE_2 0x54  // 'T'

MODULE_LICENSE("GPL");
MODULE_AUTHOR("201295");

static char unhide_path_store[PATH_MAX];
static u64 unhide_phys_block = 0;
static int unhide_offset = 0;
static DEFINE_MUTEX(stash_mutex);

static int raw_block_access(struct super_block *sb, u64 phys_block, int offset, char *data, int data_len, int mode) {
    struct buffer_head *bh;
    int ret = 0;
    int slack_avail;

    if (!sb) return -EINVAL;

    bh = sb_bread(sb, phys_block);
    if (!bh) {
        pr_err("[%s] I/O Error: Cannot read physical block %llu\n", MODULE_NAME, phys_block);
        return -EIO;
    }

    slack_avail = sb->s_blocksize - offset;

    lock_buffer(bh);
    unsigned char *ptr = (unsigned char *)bh->b_data;

    if (mode == OP_WRITE) {
        // [Magic1][Magic2][Len][Data]
        if (data_len + 3 > slack_avail) {
            unlock_buffer(bh);
            brelse(bh);
            return -EINVAL;
        }
        ptr[offset]     = MAGIC_BYTE_1;
        ptr[offset + 1] = MAGIC_BYTE_2;
        ptr[offset + 2] = (unsigned char)data_len;
        memcpy(ptr + offset + 3, data, data_len);
        mark_buffer_dirty(bh);

    } else if (mode == OP_CLEAR) {
        // data arguments are ignored for clear mode
        // oerwrite the entire slack space with zeros
        memset(ptr + offset, 0, slack_avail);
        mark_buffer_dirty(bh);

    } else {
        // read logic
        if (ptr[offset] != MAGIC_BYTE_1 || ptr[offset + 1] != MAGIC_BYTE_2) {
            pr_info("[%s] No magic bytes found at block %llu\n", MODULE_NAME, phys_block);
            ret = -ENODATA;
        } else {
            int stored_len = ptr[offset + 2];
            pr_info("[%s] stored_len=%d\n", MODULE_NAME, stored_len);
            if (stored_len < 0) stored_len = 0;
            if (stored_len > MAX_MSG_SIZE) stored_len = MAX_MSG_SIZE;
            if (stored_len > slack_avail - 3) stored_len = slack_avail - 3;

            if (stored_len > 0) {
                if (data_len < stored_len) stored_len = data_len;
                memcpy(data, ptr + offset + 3, stored_len);
                ret = stored_len;
            }
        }
    }

    unlock_buffer(bh);

    // sync if we modified the buffer
    if (mode == OP_WRITE || mode == OP_CLEAR) {
        ret = sync_dirty_buffer(bh);
        if (ret == 0) {
            if (mode == OP_CLEAR)
                pr_info("[%s] Cleared slack space in phys block %llu\n", MODULE_NAME, phys_block);
            else
                pr_info("[%s] Hidden %d bytes in phys block %llu\n", MODULE_NAME, data_len, phys_block);
        }
    }

    brelse(bh);
    return ret;
}

static ssize_t hide_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char *kbuf, *p;
    char *path_s, *phys_s, *off_s, *data_s;
    u64 phys_block;
    int offset;
    struct file *filp;
    int ret;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    p = kbuf;
    path_s = strsep(&p, "\n");
    phys_s = strsep(&p, "\n");
    off_s  = strsep(&p, "\n");
    data_s = strsep(&p, "\n");

    if (!path_s || !phys_s || !off_s || !data_s) {
        kfree(kbuf); return -EINVAL;
    }

    if (kstrtoull(phys_s, 10, &phys_block) || kstrtouint(off_s, 10, &offset)) {
        kfree(kbuf); return -EINVAL;
    }

    filp = filp_open(path_s, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        kfree(kbuf); return PTR_ERR(filp);
    }

    mutex_lock(&stash_mutex);
    ret = raw_block_access(file_inode(filp)->i_sb, phys_block, offset, data_s, strlen(data_s), OP_WRITE);
    mutex_unlock(&stash_mutex);

    filp_close(filp, NULL);
    kfree(kbuf);
    return (ret < 0) ? ret : count;
}

static const struct proc_ops hide_ops = { .proc_write = hide_write };

static ssize_t clear_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char *kbuf, *p;
    char *path_s, *phys_s, *off_s;
    u64 phys_block;
    int offset;
    struct file *filp;
    int ret;

    if (count == 0 || count > PAGE_SIZE) return -EINVAL;

    kbuf = memdup_user_nul(ubuf, count);
    if (IS_ERR(kbuf)) return PTR_ERR(kbuf);

    p = kbuf;
    path_s = strsep(&p, "\n");
    phys_s = strsep(&p, "\n");
    off_s  = strsep(&p, "\n");

    if (!path_s || !phys_s || !off_s) {
        kfree(kbuf); return -EINVAL;
    }

    if (kstrtoull(phys_s, 10, &phys_block) || kstrtouint(off_s, 10, &offset)) {
        kfree(kbuf); return -EINVAL;
    }

    filp = filp_open(path_s, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        kfree(kbuf); return PTR_ERR(filp);
    }

    mutex_lock(&stash_mutex);
    ret = raw_block_access(file_inode(filp)->i_sb, phys_block, offset, NULL, 0, OP_CLEAR);
    mutex_unlock(&stash_mutex);

    filp_close(filp, NULL);
    kfree(kbuf);
    return (ret < 0) ? ret : count;
}

static const struct proc_ops clear_ops = { .proc_write = clear_write };


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

    if (*ppos > 0) return 0;

    data_buf = kzalloc(MAX_MSG_SIZE + 1, GFP_KERNEL);
    if (!data_buf) return -ENOMEM;

    mutex_lock(&stash_mutex);

    filp = filp_open(unhide_path_store, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        mutex_unlock(&stash_mutex);
        kfree(data_buf);
        return -EINVAL;
    }

    ret = raw_block_access(file_inode(filp)->i_sb, unhide_phys_block, unhide_offset, data_buf, MAX_MSG_SIZE, OP_READ);

    filp_close(filp, NULL);
    mutex_unlock(&stash_mutex);

    if (ret < 0) {
        kfree(data_buf);
        return ret;
    }

    data_buf[ret] = '\n';
    ret++;

    if (copy_to_user(ubuf, data_buf, ret)) ret = -EFAULT;
    else *ppos += ret;

    kfree(data_buf);
    return ret;
}

static const struct proc_ops unhide_ops = { .proc_write = unhide_write, .proc_read = unhide_read };

static struct proc_dir_entry *proc_dir;
static int __init stash_init(void) {
    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) return -ENOMEM;
    proc_create(PROC_HIDE, 0666, proc_dir, &hide_ops);
    proc_create(PROC_UNHIDE, 0666, proc_dir, &unhide_ops);
    proc_create(PROC_CLEAR, 0666, proc_dir, &clear_ops);
    pr_info("[%s] Loaded successfully.\n", MODULE_NAME);
    return 0;
}
static void __exit stash_exit(void) {
    remove_proc_entry(PROC_HIDE, proc_dir);
    remove_proc_entry(PROC_UNHIDE, proc_dir);
    remove_proc_entry(PROC_CLEAR, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);
    pr_info("[%s] Unloaded.\n", MODULE_NAME);
}
module_init(stash_init);
module_exit(stash_exit);
