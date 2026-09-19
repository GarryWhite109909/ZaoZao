// ringbuf_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUF_SIZE 4096

static char ring[BUF_SIZE];
static size_t head = 0;

int write_ring(const char *data, size_t len) {
    if (data == NULL) return -1;
    if (len > BUF_SIZE) return -1;
    size_t end = head + len;
    if (end > BUF_SIZE) {
        size_t first = BUF_SIZE - head;
        memcpy(ring + head, data, first);
        memcpy(ring, data + first, len - first);
    } else {
        memcpy(ring + head, data, len);
    }
    head = end % BUF_SIZE;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    write_ring(argv[1], strlen(argv[1]));
    return 0;
}

