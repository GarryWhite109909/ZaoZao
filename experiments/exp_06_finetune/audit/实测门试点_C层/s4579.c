#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    char *buffer;
    size_t size;
} Buffer;

static int process_data(Buffer *buf, const char *input, size_t input_len) {
    if (!buf || !input || input_len == 0) {
        return -1;
    }
    
    if (input_len > MAX_BUF_SIZE) {
        fprintf(stderr, "Input too large\n");
        return -1;
    }
    
    buf->buffer = (char *)malloc(input_len + 1);
    if (!buf->buffer) {
        return -1;
    }
    buf->size = input_len;
    
    memcpy(buf->buffer, input, input_len);
    buf->buffer[input_len] = '\0';
    
    return 0;
}

static void cleanup_buffer(Buffer *buf) {
    if (buf) {
        SAFE_FREE(buf->buffer);
        buf->size = 0;
    }
}

int main(int argc, char *argv[]) {
    Buffer buf = {0};
    char local_buf[MAX_BUF_SIZE];
    
    if (argc < 2) {
        return 1;
    }
    
    size_t len = strnlen(argv[1], MAX_BUF_SIZE - 1);
    if (len == MAX_BUF_SIZE - 1) {
        fprintf(stderr, "Argument too long\n");
        return 1;
    }
    
    memcpy(local_buf, argv[1], len);
    local_buf[len] = '\0';
    
    if (process_data(&buf, local_buf, len) != 0) {
        cleanup_buffer(&buf);
        return 1;
    }
    
    printf("Processed: %s\n", buf.buffer);
    cleanup_buffer(&buf);
    
    return 0;
}

