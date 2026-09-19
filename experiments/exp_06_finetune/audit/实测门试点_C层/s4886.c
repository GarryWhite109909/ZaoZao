#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *data;
    size_t len;
} Buffer;

int process_data(Buffer *buf, const char *input) {
    if (buf == NULL || input == NULL) {
        return -1;
    }

    size_t input_len = strlen(input);
    if (input_len >= MAX_BUF_SIZE) {
        return -2;
    }

    buf->data = (char *)malloc(input_len + 1);
    if (buf->data == NULL) {
        return -3;
    }

    strcpy(buf->data, input);
    buf->len = input_len;
    return 0;
}

void cleanup_buffer(Buffer *buf) {
    if (buf != NULL && buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;  /* 防止悬垂指针 */
        buf->len = 0;
    }
}

int main() {
    Buffer my_buf = {NULL, 0};
    const char *user_input = "Hello, secure world!";
    
    if (process_data(&my_buf, user_input) == 0) {
        printf("Buffer content: %s\n", my_buf.data);
        printf("Buffer length: %zu\n", my_buf.len);
    } else {
        printf("Error processing data\n");
    }
    
    cleanup_buffer(&my_buf);
    return 0;
}

