#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while (0)

typedef struct {
    char *data;
    size_t len;
} Buffer;

static int init_buffer(Buffer *buf, size_t size) {
    if (!buf || size == 0 || size > MAX_BUF_SIZE) {
        return -1;
    }
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        return -1;
    }
    buf->len = size;
    return 0;
}

static int copy_to_buffer(Buffer *dst, const char *src, size_t src_len) {
    if (!dst || !src) {
        return -1;
    }
    if (src_len >= dst->len) {
        return -1;
    }
    memcpy(dst->data, src, src_len);
    dst->data[src_len] = '\0';
    return 0;
}

static void destroy_buffer(Buffer *buf) {
    if (buf) {
        SAFE_FREE(buf->data);
        buf->len = 0;
    }
}

int main(void) {
    Buffer buf;
    char input[] = "Hello, safe world!";
    size_t input_len = strlen(input);

    if (init_buffer(&buf, 64) != 0) {
        fprintf(stderr, "Failed to init buffer\n");
        return 1;
    }

    if (copy_to_buffer(&buf, input, input_len) != 0) {
        fprintf(stderr, "Failed to copy data\n");
        destroy_buffer(&buf);
        return 1;
    }

    printf("Buffer content: %s\n", buf.data);
    destroy_buffer(&buf);
    return 0;
}

