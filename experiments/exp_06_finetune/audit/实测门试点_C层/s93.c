#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 1024
#define CHUNK_SIZE 256

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} Buffer;

int buffer_append(Buffer *buf, const char *src, size_t src_len) {
    if (buf == NULL || src == NULL) {
        return -1;
    }
    if (src_len > buf->cap - buf->len) {
        return -1;
    }
    memcpy(buf->data + buf->len, src, src_len);
    buf->len += src_len;
    return 0;
}

int process_chunk(Buffer *buf, const char *input, size_t input_len) {
    size_t offset = 0;
    while (offset < input_len) {
        size_t chunk = (input_len - offset > CHUNK_SIZE) ? CHUNK_SIZE : (input_len - offset);
        if (buffer_append(buf, input + offset, chunk) != 0) {
            return -1;
        }
        offset += chunk;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }

    size_t input_len = strlen(argv[1]);
    if (input_len > MAX_BUF * 2) {
        fprintf(stderr, "Input too large\n");
        return 1;
    }

    Buffer buf;
    buf.data = (char *)malloc(MAX_BUF);
    if (buf.data == NULL) {
        return 1;
    }
    buf.len = 0;
    buf.cap = MAX_BUF;

    int ret = process_chunk(&buf, argv[1], input_len);
    if (ret != 0) {
        free(buf.data);
        return 1;
    }

    printf("Processed: %s\n", buf.data);
    free(buf.data);
    return 0;
}

