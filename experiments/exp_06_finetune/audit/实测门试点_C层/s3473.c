#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} Buffer;

static int buffer_init(Buffer *buf, size_t initial_cap) {
    if (!buf || initial_cap == 0 || initial_cap > MAX_BUF_SIZE) {
        return -1;
    }
    buf->data = (char *)malloc(initial_cap);
    if (!buf->data) {
        return -1;
    }
    buf->len = 0;
    buf->cap = initial_cap;
    return 0;
}

static int buffer_append(Buffer *buf, const char *src, size_t src_len) {
    if (!buf || !buf->data || !src) {
        return -1;
    }
    if (src_len > MAX_BUF_SIZE - buf->len) {
        return -1;
    }
    memcpy(buf->data + buf->len, src, src_len);
    buf->len += src_len;
    buf->data[buf->len] = '\0';
    return 0;
}

static void buffer_free(Buffer *buf) {
    if (buf) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->cap = 0;
    }
}

static int process_message(const char *input, size_t input_len) {
    Buffer buf;
    const char *prefix = "MSG:";
    size_t prefix_len = strlen(prefix);

    if (input_len > MAX_BUF_SIZE - prefix_len - 1) {
        return -1;
    }

    if (buffer_init(&buf, input_len + prefix_len + 1) != 0) {
        return -1;
    }

    if (buffer_append(&buf, prefix, prefix_len) != 0) {
        buffer_free(&buf);
        return -1;
    }

    if (buffer_append(&buf, input, input_len) != 0) {
        buffer_free(&buf);
        return -1;
    }

    printf("Processed: %s\n", buf.data);
    buffer_free(&buf);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }

    size_t input_len = strlen(argv[1]);
    if (process_message(argv[1], input_len) != 0) {
        fprintf(stderr, "Failed to process message\n");
        return 1;
    }
    return 0;
}

