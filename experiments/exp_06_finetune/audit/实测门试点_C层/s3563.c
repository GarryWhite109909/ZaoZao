#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void process_buffer(Buffer *buf, const char *input, size_t input_len) {
    if (!buf || !input || input_len == 0) {
        return;
    }
    if (input_len >= MAX_BUF) {
        fprintf(stderr, "Input too large\n");
        return;
    }
    
    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        return;
    }
    
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;
}

static void cleanup_buffer(Buffer *buf) {
    if (buf) {
        SAFE_FREE(buf->data);
        buf->len = 0;
    }
}

int main(void) {
    Buffer buf = {0};
    const char *user_input = "Hello, World!";
    size_t input_size = strlen(user_input);
    
    process_buffer(&buf, user_input, input_size);
    if (!buf.data) {
        return 1;
    }
    
    printf("Processed: %s (len=%zu)\n", buf.data, buf.len);
    cleanup_buffer(&buf);
    
    return 0;
}

