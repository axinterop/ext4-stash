#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>

#define PROC_HIDE "/proc/ext4_stash/hide"
#define PROC_UNHIDE "/proc/ext4_stash/unhide"
#define PROC_CLEAR "/proc/ext4_stash/clear"
#define PROC_MAP "/proc/ext4_stash/map"

#define CHUNK_SIZE 4090  // Max data per chunk (4096 - 6 header bytes)
#define MAX_CARRIERS 1000

typedef struct {
    char path[1024];
    unsigned long long phys_block;
    int offset;
    int slack_avail;
    int used;  // 0 if available, 1 if used
} CarrierInfo;

// Get slack space info for a file
int get_slack_info(const char *path, CarrierInfo *info) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    int block_size = st.st_blksize;
    int off = st.st_size % block_size;

    if (off == 0) {
        close(fd);
        return -2;
    }

    info->offset = off;
    info->slack_avail = block_size - off;
    strncpy(info->path, path, sizeof(info->path) - 1);
    info->used = 0;

    struct fiemap *fiemap;
    int extents_size = sizeof(struct fiemap_extent);
    fiemap = malloc(sizeof(struct fiemap) + extents_size);

    memset(fiemap, 0, sizeof(struct fiemap) + extents_size);
    fiemap->fm_start = (st.st_size / block_size) * block_size;
    fiemap->fm_length = block_size;
    fiemap->fm_flags = FIEMAP_FLAG_SYNC;
    fiemap->fm_extent_count = 1;

    if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
        free(fiemap);
        close(fd);
        return -1;
    }

    if (fiemap->fm_mapped_extents == 0) {
        free(fiemap);
        close(fd);
        return -1;
    }

    info->phys_block = fiemap->fm_extents[0].fe_physical / block_size;

    free(fiemap);
    close(fd);
    return 0;
}

// Find carrier files in a directory
int find_carriers(const char *dir_path, CarrierInfo *carriers, int max_carriers) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char path[1024];
    int count = 0;

    dir = opendir(dir_path);
    if (!dir) {
        perror("Error opening directory");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL && count < max_carriers) {
        if (entry->d_name[0] == '.') continue;

        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        if (stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
            if (get_slack_info(path, &carriers[count]) == 0) {
                // Ensure enough slack space for at least small messages
                if (carriers[count].slack_avail >= 100) {
                    count++;
                }
            }
        }
    }

    closedir(dir);
    return count;
}

// Generate a unique message ID
unsigned long long generate_msg_id() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((unsigned long long)ts.tv_sec << 32) | (ts.tv_nsec & 0xFFFFFFFF);
}

// Hide data with chunking across multiple files
int do_hide(const char *data_source, int is_file, const char *carrier_dir) {
    FILE *src_file = NULL;
    unsigned char *data = NULL;
    size_t data_size = 0;
    unsigned long long msg_id = generate_msg_id();

    // Read source data
    if (is_file) {
        src_file = fopen(data_source, "rb");
        if (!src_file) {
            perror("Error opening source file");
            return -1;
        }

        fseek(src_file, 0, SEEK_END);
        data_size = ftell(src_file);
        fseek(src_file, 0, SEEK_SET);

        data = malloc(data_size);
        if (!data) {
            perror("Memory allocation failed");
            fclose(src_file);
            return -1;
        }

        size_t read_bytes = fread(data, 1, data_size, src_file);
        if (read_bytes != data_size) {
            fprintf(stderr, "Warning: Only read %zu of %zu bytes\n",
                   read_bytes, data_size);
            data_size = read_bytes;
        }
        fclose(src_file);
    } else {
        data_size = strlen(data_source);
        data = (unsigned char*)strdup(data_source);
    }

    if (data_size == 0) {
        fprintf(stderr, "Error: No data to hide\n");
        free(data);
        return -1;
    }

    // Find carrier files
    CarrierInfo carriers[MAX_CARRIERS];
    int carrier_count = find_carriers(carrier_dir, carriers, MAX_CARRIERS);

    if (carrier_count == 0) {
        fprintf(stderr, "No suitable carrier files found in %s\n", carrier_dir);
        free(data);
        return -1;
    }

    // Calculate number of chunks needed
    int total_chunks = (data_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

    if (total_chunks > carrier_count) {
        fprintf(stderr, "Error: Need %d carrier files but only found %d\n",
               total_chunks, carrier_count);
        fprintf(stderr, "Either reduce data size or add more carrier files\n");
        free(data);
        return -1;
    }

    printf("Hiding %zu bytes in %d chunks across %d carrier files (msg_id: %llu)\n",
           data_size, total_chunks, carrier_count, msg_id);

    // Send each chunk to a different carrier file
    for (int chunk_idx = 0; chunk_idx < total_chunks; chunk_idx++) {
        size_t chunk_start = chunk_idx * CHUNK_SIZE;
        size_t chunk_size = (chunk_start + CHUNK_SIZE <= data_size) ?
                           CHUNK_SIZE : data_size - chunk_start;

        // Find an unused carrier
        CarrierInfo *carrier = NULL;
        for (int i = 0; i < carrier_count; i++) {
            if (!carriers[i].used && carriers[i].slack_avail >= chunk_size + 6) {
                carrier = &carriers[i];
                carrier->used = 1;
                break;
            }
        }

        if (!carrier) {
            fprintf(stderr, "Error: No suitable carrier for chunk %d\n", chunk_idx);
            free(data);
            return -1;
        }

        // Prepare message for kernel
        // Format: msg_id\nchunk_idx\ntotal_chunks\npath\nphys_block\noffset\ndata
        int header_size = snprintf(NULL, 0, "%llu\n%d\n%d\n%s\n%llu\n%d\n",
                                 msg_id, chunk_idx, total_chunks,
                                 carrier->path, carrier->phys_block,
                                 carrier->offset);

        char *buffer = malloc(header_size + chunk_size + 1);
        if (!buffer) {
            perror("Memory allocation failed");
            free(data);
            return -1;
        }

        int written = snprintf(buffer, header_size + 1,
                              "%llu\n%d\n%d\n%s\n%llu\n%d\n",
                              msg_id, chunk_idx, total_chunks,
                              carrier->path, carrier->phys_block,
                              carrier->offset);

        // Append binary data
        memcpy(buffer + written, data + chunk_start, chunk_size);

        int fd = open(PROC_HIDE, O_WRONLY);
        if (fd < 0) {
            perror("Module /proc/hide missing");
            free(buffer);
            free(data);
            return -1;
        }

        // Write header + binary data
        if (write(fd, buffer, written + chunk_size) < 0) {
            perror("Write failed");
            close(fd);
            free(buffer);
            free(data);
            return -1;
        }

        close(fd);
        free(buffer);

        printf("  Chunk %d/%d (%zu bytes) -> %s (block %llu, offset %d)\n",
               chunk_idx + 1, total_chunks, chunk_size, carrier->path,
               carrier->phys_block, carrier->offset);
    }

    free(data);
    printf("Success: All %d chunks hidden (message ID: %llu)\n", total_chunks, msg_id);
    printf("Use 'stash_cli unhide %llu' to recover\n", msg_id);
    return 0;
}

// Unhide data by message ID
void do_unhide(unsigned long long msg_id) {
    char buffer[8192];

    // Write message ID to kernel
    int fd_write = open(PROC_UNHIDE, O_WRONLY);
    if (fd_write < 0) {
        perror("Module /proc/unhide missing");
        return;
    }

    snprintf(buffer, sizeof(buffer), "%llu", msg_id);
    if (write(fd_write, buffer, strlen(buffer)) < 0) {
        perror("Write failed");
        close(fd_write);
        return;
    }
    close(fd_write);

    // Read recovered data
    int fd_read = open(PROC_UNHIDE, O_RDONLY);
    if (fd_read < 0) {
        perror("Read failed");
        return;
    }

    printf("Recovering message %llu:\n", msg_id);
    printf("================================\n");

    ssize_t total_read = 0;
    while (1) {
        ssize_t len = read(fd_read, buffer, sizeof(buffer));
        if (len <= 0) break;

        // Write to stdout (could be binary)
        fwrite(buffer, 1, len, stdout);
        total_read += len;
    }

    printf("\n================================\n");
    printf("Total recovered: %zd bytes\n", total_read);

    if (total_read == 0) {
        printf("No data found for message ID %llu\n", msg_id);
    }

    close(fd_read);
}

// Clear a message by ID
void do_clear(unsigned long long msg_id) {
    char buffer[64];

    int fd = open(PROC_CLEAR, O_WRONLY);
    if (fd < 0) {
        perror("Module /proc/clear missing");
        return;
    }

    snprintf(buffer, sizeof(buffer), "%llu", msg_id);

    if (write(fd, buffer, strlen(buffer)) < 0) {
        perror("Clear failed");
    } else {
        printf("Success: Removed message %llu from map\n", msg_id);
    }

    close(fd);
}

// List all stashed messages
void do_list_map() {
    FILE *fp = fopen(PROC_MAP, "r");
    if (!fp) {
        perror("Cannot open map");
        return;
    }

    char line[256];
    printf("Current stash map:\n");

    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }

    fclose(fp);
}

// Test: create some dummy carrier files
void create_test_carriers(const char *dir_path, int count) {
    char path[1024];
    FILE *fp;

    printf("Creating %d test carrier files in %s...\n", count, dir_path);

    for (int i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/carrier_%d.txt", dir_path, i);
        fp = fopen(path, "w");
        if (fp) {
            // Write some data to create slack space
            for (int j = 0; j < 100; j++) {
                fprintf(fp, "This is carrier file %d, line %d\n", i, j);
            }
            fclose(fp);
            printf("  Created: %s\n", path);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Slack Space Hider (Chunking Edition)\n");
        printf("=====================================\n");
        printf("Usage:\n");
        printf("  %s hide <file> <carrier_dir>\n", argv[0]);
        printf("  %s hide --text \"text\" <carrier_dir>\n", argv[0]);
        printf("  %s test <carrier_dir> <count>\n", argv[0]);
        printf("  %s unhide <msg_id>\n", argv[0]);
        printf("  %s clear <msg_id>\n", argv[0]);
        printf("  %s map\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s test /tmp/carriers 10\n", argv[0]);
        printf("  %s hide secret.txt /tmp/carriers\n", argv[0]);
        printf("  %s hide --text \"my secret\" /tmp/carriers\n", argv[0]);
        printf("  %s unhide 1234567890123456789\n", argv[0]);
        printf("  %s clear 1234567890123456789\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "hide") == 0) {
        if (argc < 4) {
            printf("Error: hide requires source and carrier directory\n");
            return 1;
        }

        if (strcmp(argv[2], "--text") == 0 && argc >= 5) {
            do_hide(argv[3], 0, argv[4]);  // Text string
        } else {
            do_hide(argv[2], 1, argv[3]);  // File
        }

    } else if (strcmp(argv[1], "test") == 0 && argc >= 4) {
        int count = atoi(argv[3]);
        create_test_carriers(argv[2], count > 0 ? count : 10);

    } else if (strcmp(argv[1], "unhide") == 0 && argc >= 3) {
        unsigned long long msg_id = strtoull(argv[2], NULL, 10);
        if (msg_id == 0) {
            printf("Error: Invalid message ID\n");
            return 1;
        }
        do_unhide(msg_id);

    } else if (strcmp(argv[1], "clear") == 0 && argc >= 3) {
        unsigned long long msg_id = strtoull(argv[2], NULL, 10);
        if (msg_id == 0) {
            printf("Error: Invalid message ID\n");
            return 1;
        }
        do_clear(msg_id);

    } else if (strcmp(argv[1], "map") == 0) {
        do_list_map();

    } else {
        printf("Invalid command.\n");
        return 1;
    }

    return 0;
}
