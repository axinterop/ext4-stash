#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#define PROC_HIDE "/proc/ext4_stash/hide"
#define PROC_UNHIDE "/proc/ext4_stash/unhide"

void usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s hide <abs_filepath> <message>\n", prog);
    fprintf(stderr, "  %s unhide <abs_filepath>\n", prog);
    exit(1);
}

void do_hide(const char *path, const char *msg) {
    int fd = open(PROC_HIDE, O_WRONLY);
    if (fd < 0) {
        perror("Error opening kernel module interface");
        fprintf(stderr, "Is ext4_stash.ko loaded?\n");
        exit(1);
    }

    // Format: "path\nmsg"
    // Note: Kernel module expects strict single write logic for simplicity
    char buffer[4096];
    snprintf(buffer, sizeof(buffer), "%s\n%s", path, msg);

    int len = strlen(buffer);
    if (write(fd, buffer, len) < 0) {
        perror("Error writing to slack space");
    } else {
        printf("Success: Data hidden in slack space of %s\n", path);
    }

    close(fd);
}

void do_unhide(const char *path) {
    int fd_write = open(PROC_UNHIDE, O_WRONLY);
    if (fd_write < 0) {
        perror("Error opening kernel module interface (write)");
        exit(1);
    }

    // Step 1: Tell kernel which file to target
    if (write(fd_write, path, strlen(path)) < 0) {
        perror("Error setting target file");
        close(fd_write);
        exit(1);
    }
    close(fd_write);

    // Step 2: Read the result
    int fd_read = open(PROC_UNHIDE, O_RDONLY);
    if (fd_read < 0) {
        perror("Error opening kernel module interface (read)");
        exit(1);
    }

    char buffer[1024];
    int bytes = read(fd_read, buffer, sizeof(buffer) - 1);
    if (bytes < 0) {
        perror("Error reading hidden data");
    } else if (bytes == 0) {
        printf("No data found or empty.\n");
    } else {
        buffer[bytes] = '\0';
        // Note: Kernel adds a newline for us
        printf("Recovered data: %s", buffer);
    }

    close(fd_read);
}

int main(int argc, char *argv[]) {
    if (argc < 3) usage(argv[0]);

    const char *cmd = argv[1];
    const char *path = argv[2];

    if (path[0] != '/') {
        fprintf(stderr, "Error: File path must be absolute (start with /)\n");
        exit(1);
    }

    if (strcmp(cmd, "hide") == 0) {
        if (argc < 4) usage(argv[0]);
        do_hide(path, argv[3]);
    } else if (strcmp(cmd, "unhide") == 0) {
        do_unhide(path);
    } else {
        usage(argv[0]);
    }

    return 0;
}
