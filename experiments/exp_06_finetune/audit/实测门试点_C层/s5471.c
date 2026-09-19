#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    char *data;
    size_t len;
} Buffer;

static int process_buffer(Buffer *buf, const char *input, size_t input_len) {
    if (!buf || !input) {
        return -1;
    }
    
    if (input_len >= MAX_BUF_SIZE) {
        fprintf(stderr, "Input too large\n");
        return -1;
    }
    
    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        return -1;
    }
    
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;
    return 0;
}

int main(int argc, char *argv[]) {
    Buffer buf = {0};
    char input[MAX_BUF_SIZE];
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    size_t input_len = strnlen(argv[1], MAX_BUF_SIZE - 1);
    if (input_len == MAX_BUF_SIZE - 1) {
        fprintf(stderr, "Input too long\n");
        return 1;
    }
    
    memcpy(input, argv[1], input_len);
    input[input_len] = '\0';
    
    if (process_buffer(&buf, input, input_len) != 0) {
        fprintf(stderr, "Processing failed\n");
        return 1;
    }
    
    printf("Processed: %s\n", buf.data);
    SAFE_FREE(buf.data);
    
    return 0;
}

