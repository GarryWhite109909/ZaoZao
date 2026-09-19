#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024

typedef struct {
    char *data;
    size_t length;
} Buffer;

Buffer *create_buffer(size_t size) {
    if (size == 0 || size > MAX_BUF_SIZE) {
        fprintf(stderr, "Invalid buffer size\n");
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
    
    buf->length = size;
    memset(buf->data, 0, size);
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (buf == NULL) {
        return;
    }
    
    if (buf->data != NULL) {
        memset(buf->data, 0, buf->length);  // 清除敏感数据
        free(buf->data);
        buf->data = NULL;                    // 防止悬垂指针
    }
    
    free(buf);
}

void safe_copy(Buffer *dst, const Buffer *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    
    if (dst->data == NULL || src->data == NULL) {
        return;
    }
    
    size_t copy_size = (dst->length < src->length) ? dst->length : src->length;
    memcpy(dst->data, src->data, copy_size);
}

int main() {
    Buffer *buf1 = create_buffer(512);
    Buffer *buf2 = create_buffer(256);
    
    if (!buf1 || !buf2) {
        destroy_buffer(buf1);
        destroy_buffer(buf2);
        return 1;
    }
    
    strcpy(buf1->data, "Hello, secure world!");
    safe_copy(buf2, buf1);
    
    printf("Copied: %s\n", buf2->data);
    
    destroy_buffer(buf1);
    destroy_buffer(buf2);
    
    return 0;
}

