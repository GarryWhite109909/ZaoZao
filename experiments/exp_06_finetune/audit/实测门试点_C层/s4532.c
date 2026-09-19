#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    char *data;
    size_t len;
    int is_valid;
} Buffer;

static int process_buffer(Buffer *buf, const char *input, size_t input_len) {
    if (!buf || !input || input_len >= MAX_BUF_SIZE) {
        return -1;
    }

    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        return -1;
    }

    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;
    buf->is_valid = 1;
    return 0;
}

static void destroy_buffer(Buffer *buf) {
    if (buf) {
        SAFE_FREE(buf->data);
        buf->len = 0;
        buf->is_valid = 0;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    Buffer buf = {0};
    size_t input_len = strlen(argv[1]);

    if (process_buffer(&buf, argv[1], input_len) != 0) {
        fprintf(stderr, "Buffer processing failed\n");
        return 1;
    }

    printf("Processed: %s (len=%zu)\n", buf.data, buf.len);

    destroy_buffer(&buf);
    return 0;
}

