#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024

typedef struct {
    char *data;
    size_t len;
    size_t capacity;
} Buffer;

int buffer_init(Buffer *buf, size_t initial_capacity) {
    if (!buf || initial_capacity == 0) {
        return -1;
    }
    buf->data = (char *)malloc(initial_capacity);
    if (!buf->data) {
        return -1;
    }
    buf->len = 0;
    buf->capacity = initial_capacity;
    return 0;
}

void buffer_free(Buffer *buf) {
    if (buf) {
        free(buf->data);
        buf->data = NULL;  // line 24: 防止悬空指针
        buf->len = 0;
        buf->capacity = 0;
    }
}

int buffer_append(Buffer *buf, const char *src, size_t src_len) {
    if (!buf || !src || !buf->data) {
        return -1;
    }
    // line 31: 边界检查，防止缓冲区溢出
    if (buf->len + src_len > buf->capacity) {
        return -1;
    }
    memcpy(buf->data + buf->len, src, src_len);  // line 34
    buf->len += src_len;
    buf->data[buf->len] = '\0';
    return 0;
}

int main() {
    Buffer buf;
    char input[256];
    
    if (buffer_init(&buf, 64) != 0) {
        fprintf(stderr, "Buffer init failed\n");
        return 1;
    }
    
    printf("Enter data (max 255 chars): ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        buffer_free(&buf);
        return 1;
    }
    
    size_t input_len = strlen(input);
    if (input_len > 0 && input[input_len - 1] == '\n') {
        input[input_len - 1] = '\0';
        input_len--;
    }
    
    // line 59: 调用安全追加函数
    if (buffer_append(&buf, input, input_len) != 0) {
        fprintf(stderr, "Buffer append failed: data too large\n");
        buffer_free(&buf);
        return 1;
    }
    
    printf("Buffer content: %s\n", buf.data);
    
    buffer_free(&buf);  // line 68: 释放后置NULL
    return 0;
}

