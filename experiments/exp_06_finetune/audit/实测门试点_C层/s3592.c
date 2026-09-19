#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
    if (size == 0 || size > MAX_BUF_SIZE) {
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
    buf->len = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) {
        return;
    }
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;  // 防御：free后置NULL，防止悬垂指针
    }
    free(buf);
}

int copy_to_buffer(Buffer *dst, const char *src, size_t src_len) {
    if (!dst || !src || !dst->data) {
        return -1;
    }
    if (src_len >= dst->len) {  // 防御：边界检查，拒绝超长拷贝
        return -1;
    }
    memcpy(dst->data, src, src_len);
    dst->data[src_len] = '\0';
    return 0;
}

int main(void) {
    Buffer *buf = create_buffer(128);
    if (!buf) {
        return 1;
    }
    
    char input[] = "hello";
    if (copy_to_buffer(buf, input, strlen(input)) != 0) {
        destroy_buffer(buf);
        return 1;
    }
    
    printf("Content: %s\n", buf->data);
    destroy_buffer(buf);
    return 0;
}

