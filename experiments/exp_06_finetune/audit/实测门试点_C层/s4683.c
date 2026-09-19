#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 128

typedef struct {
    char *data;
    size_t len;
} SafeBuffer;

int safe_buffer_init(SafeBuffer *buf, size_t size) {
    if (!buf || size == 0 || size > MAX_BUF_SIZE) {
        return -1;
    }
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        return -1;
    }
    buf->len = size;
    memset(buf->data, 0, size);
    return 0;
}

void safe_buffer_free(SafeBuffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
    }
}

int process_message(const char *input, size_t input_len) {
    if (!input || input_len == 0 || input_len >= MAX_BUF_SIZE) {
        return -1;
    }
    
    SafeBuffer msg;
    if (safe_buffer_init(&msg, input_len + 1) != 0) {
        return -1;
    }
    
    memcpy(msg.data, input, input_len);
    msg.data[input_len] = '\0';
    
    printf("Message: %s\n", msg.data);
    
    safe_buffer_free(&msg);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }
    
    size_t len = strlen(argv[1]);
    if (len == 0 || len >= MAX_BUF_SIZE) {
        fprintf(stderr, "Invalid input length\n");
        return 1;
    }
    
    return process_message(argv[1], len);
}

