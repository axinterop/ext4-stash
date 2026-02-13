#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <sys/stat.h>

#define PROC_HIDE "/proc/ext4_stash/hide"
#define PROC_UNHIDE "/proc/ext4_stash/unhide"
#define PROC_CLEAR "/proc/ext4_stash/clear"

int get_slack_info(const char *path, unsigned long long *phys_block, int *offset) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Error opening target file");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat failed");
        close(fd); return -1;
    }

    int block_size = st.st_blksize;
    int off = st.st_size % block_size;

    if (off == 0) {
        fprintf(stderr, "Error: No slack space (file size %ld aligns with block %d).\n", st.st_size, block_size);
        close(fd); return -2;
    }
    *offset = off;

    struct fiemap *fiemap;
    int extents_size = sizeof(struct fiemap_extent);
    fiemap = malloc(sizeof(struct fiemap) + extents_size);

    memset(fiemap, 0, sizeof(struct fiemap) + extents_size);
    fiemap->fm_start = (st.st_size / block_size) * block_size; // start of last block
    fiemap->fm_length = block_size;
    fiemap->fm_flags = FIEMAP_FLAG_SYNC;
    fiemap->fm_extent_count = 1;

    if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
        perror("ioctl FIEMAP failed");
        free(fiemap); close(fd); return -1;
    }

    if (fiemap->fm_mapped_extents == 0) {
        fprintf(stderr, "Error: Block not mapped.\n");
        free(fiemap); close(fd); return -1;
    }

    *phys_block = fiemap->fm_extents[0].fe_physical / block_size;

    free(fiemap);
    close(fd);
    return 0;
}

void do_hide(const char *path, const char *msg) {
    unsigned long long phys_block;
    int offset;

    if (get_slack_info(path, &phys_block, &offset) != 0) exit(1);

    char buffer[4096];
    // Protocol: path \n phys \n off \n msg
    snprintf(buffer, sizeof(buffer), "%s\n%llu\n%d\n%s", path, phys_block, offset, msg);

    int fd = open(PROC_HIDE, O_WRONLY);
    if (fd < 0) { perror("Module /proc/hide missing"); exit(1); }

    if (write(fd, buffer, strlen(buffer)) < 0) perror("Write failed");
    else printf("Success: Hidden in block %llu (offset %d)\n", phys_block, offset);

    close(fd);
}

void do_unhide(const char *path) {
    unsigned long long phys_block;
    int offset;

    if (get_slack_info(path, &phys_block, &offset) != 0) exit(1);

    char buffer[4096];
    snprintf(buffer, sizeof(buffer), "%s\n%llu\n%d", path, phys_block, offset);

    int fd_write = open(PROC_UNHIDE, O_WRONLY);
    if (fd_write < 0) { perror("Module /proc/unhide missing"); exit(1); }
    write(fd_write, buffer, strlen(buffer));
    close(fd_write);

    int fd_read = open(PROC_UNHIDE, O_RDONLY);
    if (fd_read < 0) { perror("Read failed"); exit(1); }

    int len = read(fd_read, buffer, sizeof(buffer)-1);
    if (len > 0) {
        buffer[len] = 0;
        printf("Recovered: %s", buffer);
    } else {
        printf("No data found.\n");
    }
    close(fd_read);
}

void do_clear(const char *path) {
    unsigned long long phys_block;
    int offset;

    if (get_slack_info(path, &phys_block, &offset) != 0) exit(1);

    char buffer[4096];
    // Protocol: path \n phys \n off
    snprintf(buffer, sizeof(buffer), "%s\n%llu\n%d", path, phys_block, offset);

    int fd = open(PROC_CLEAR, O_WRONLY);
    if (fd < 0) { perror("Module /proc/clear missing"); exit(1); }

    if (write(fd, buffer, strlen(buffer)) < 0) perror("Clear failed");
    else printf("Success: Slack space cleared for %s\n", path);

    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s hide <abs_path> <msg>\n", argv[0]);
        printf("       %s unhide <abs_path>\n", argv[0]);
        printf("       %s clear <abs_path>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "hide") == 0 && argc >= 4) do_hide(argv[2], argv[3]);
    else if (strcmp(argv[1], "unhide") == 0) do_unhide(argv[2]);
    else if (strcmp(argv[1], "clear") == 0) do_clear(argv[2]);
    else printf("Invalid command.\n");
    return 0;
}
