#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t size;
} Buffer;

Buffer *create_buffer(size_t size) {
    if (size == 0) {
        return NULL;
    }
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) {
        return NULL;
    }
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->size = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) {
        return;
    }
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;  // line 29: 置NULL防止悬垂指针
    }
    buf->size = 0;
    free(buf);            // line 32: 释放结构体本身
}

void safe_process(Buffer *buf, const char *input) {
    if (!buf || !buf->data || !input) {
        return;
    }
    size_t input_len = strlen(input);
    if (input_len >= buf->size) {  // line 39: 边界检查
        return;
    }
    memcpy(buf->data, input, input_len + 1);  // line 41: 包含'\0'
    printf("Data: %s\n", buf->data);
}

int main() {
    Buffer *buf = create_buffer(64);
    if (!buf) {
        return 1;
    }
    safe_process(buf, "test input");
    destroy_buffer(buf);  // line 51: 正常释放
    destroy_buffer(buf);  // line 52: 重复释放测试（安全）
    return 0;
}

