#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_PATH 256
#define BASE_DIR "/var/lib/orders"

/* Validate order ID: only alphanumeric, max 20 chars */
static int is_valid_order_id(const char *id) {
    if (id == NULL || strlen(id) == 0 || strlen(id) > 20) {
        return 0;
    }
    for (size_t i = 0; i < strlen(id); i++) {
        if (!((id[i] >= '0' && id[i] <= '9') ||
              (id[i] >= 'a' && id[i] <= 'z') ||
              (id[i] >= 'A' && id[i] <= 'Z'))) {
            return 0;
        }
    }
    return 1;
}

static int load_order(const char *order_id, char *out, size_t out_size) {
    char path[MAX_PATH];
    int fd;

    if (!is_valid_order_id(order_id)) {
        fprintf(stderr, "Invalid order ID\n");
        return -1;
    }

    /* Build path safely: BASE_DIR + "/" + validated ID */
    if (snprintf(path, sizeof(path), "%s/%s", BASE_DIR, order_id) >= sizeof(path)) {
        fprintf(stderr, "Path too long\n");
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    ssize_t n = read(fd, out, out_size - 1);
    close(fd);
    if (n < 0) {
        perror("read");
        return -1;
    }
    out[n] = '\0';
    return 0;
}

int main(int argc, char *argv[]) {
    char buffer[128];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <order_id>\n", argv[0]);
        return 1;
    }

    if (load_order(argv[1], buffer, sizeof(buffer)) == 0) {
        printf("Order: %s\n", buffer);
    }
    return 0;
}

