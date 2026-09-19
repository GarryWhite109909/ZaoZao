#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    char *data;
    size_t len;
} Buffer;

static int process_buffer(Buffer *buf, const char *input, size_t input_len) {
    if (!buf || !input || input_len == 0) {
        return -1;
    }
    if (input_len > MAX_BUF_SIZE) {
        return -2;
    }
    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        return -3;
    }
    buf->len = input_len;
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    return 0;
}

int main(void) {
    Buffer my_buf = {0};
    const char *user_input = "Hello, secure world!";
    size_t user_len = strlen(user_input);
    
    if (process_buffer(&my_buf, user_input, user_len) != 0) {
        fprintf(stderr, "Buffer processing failed\n");
        return 1;
    }
    
    printf("Processed: %s (len=%zu)\n", my_buf.data, my_buf.len);
    
    SAFE_FREE(my_buf.data);
    my_buf.len = 0;
    
    if (my_buf.data == NULL) {
        printf("Buffer safely freed\n");
    }
    
    return 0;
}

