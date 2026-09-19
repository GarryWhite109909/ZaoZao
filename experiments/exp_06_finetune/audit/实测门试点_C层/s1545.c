#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_PATH 256
#define ORDER_DIR "/var/lib/orders/"

void read_order_file(const char *user_input) {
    char filepath[MAX_PATH];
    char buffer[512];
    int fd;
    ssize_t bytes_read;

    // Construct the file path from user input
    snprintf(filepath, sizeof(filepath), "%s%s", ORDER_DIR, user_input);

    // Open and read the file
    fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        printf("Order file not found.\n");
        return;
    }

    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read == -1) {
        perror("read");
        close(fd);
        return;
    }
    buffer[bytes_read] = '\0';
    close(fd);

    printf("Order details:\n%s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <order_id>\n", argv[0]);
        return 1;
    }

    read_order_file(argv[1]);
    return 0;
}

