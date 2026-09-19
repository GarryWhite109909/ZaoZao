#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* data;
    size_t len;
} Buffer;

Buffer* buffer_create(size_t size) {
    Buffer* buf = (Buffer*)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = (char*)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

void buffer_destroy(Buffer* buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;  // 防御：释放后置NULL
    free(buf);
}

int buffer_append(Buffer* buf, const char* src, size_t src_len) {
    if (!buf || !buf->data || !src) return -1;  // 防御：空指针检查
    if (src_len > buf->len) return -1;           // 防御：边界检查
    
    memcpy(buf->data, src, src_len);
    buf->len = src_len;
    return 0;
}

int main() {
    Buffer* buf = buffer_create(64);
    if (!buf) return 1;
    
    const char* msg = "Hello, secure memory!";
    if (buffer_append(buf, msg, strlen(msg)) != 0) {
        buffer_destroy(buf);
        return 1;
    }
    
    printf("Data: %s\n", buf->data);
    buffer_destroy(buf);  // 释放后buf已置NULL
    // 后续不再访问buf，避免UAF
    return 0;
}

