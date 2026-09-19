#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;          // line 20: 置NULL防止悬垂指针
    free(buf);
}

int process(Buffer *buf) {
    if (!buf || !buf->data) {  // line 24: 双重校验
        return -1;
    }
    if (buf->len < 4) return -1;
    memcpy(buf->data, "TEST", 4);
    return 0;
}

int main() {
    Buffer *b = create_buffer(16);
    if (!b) return 1;
    
    if (process(b) == 0) {
        printf("processed: %.4s\n", b->data);
    }
    
    destroy_buffer(b);          // line 38: 释放后不再使用
    b = NULL;                   // line 39: 调用方也置NULL
    
    // 后续代码不再引用b，避免UAF
    return 0;
}

