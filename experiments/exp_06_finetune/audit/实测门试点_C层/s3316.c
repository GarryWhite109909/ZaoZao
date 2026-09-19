#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *buffer;
    size_t size;
} SafeBuffer;

int init_buffer(SafeBuffer *sb, size_t requested_size) {
    if (sb == NULL) {
        return -1;
    }
    
    // 边界检查：拒绝过大的内存请求
    if (requested_size > MAX_BUF_SIZE) {
        fprintf(stderr, "Buffer size %zu exceeds limit %d\n", 
                requested_size, MAX_BUF_SIZE);
        return -1;
    }
    
    sb->buffer = (char *)malloc(requested_size);
    if (sb->buffer == NULL) {
        return -1;
    }
    
    sb->size = requested_size;
    memset(sb->buffer, 0, requested_size);
    return 0;
}

void safe_free(SafeBuffer *sb) {
    if (sb != NULL && sb->buffer != NULL) {
        free(sb->buffer);
        sb->buffer = NULL;  // 防止悬空指针
        sb->size = 0;
    }
}

int copy_data(SafeBuffer *dest, const char *src, size_t src_len) {
    if (dest == NULL || src == NULL || dest->buffer == NULL) {
        return -1;
    }
    
    // 边界检查：确保不会发生缓冲区溢出
    if (src_len >= dest->size) {
        fprintf(stderr, "Source length %zu exceeds dest size %zu\n", 
                src_len, dest->size);
        return -1;
    }
    
    memcpy(dest->buffer, src, src_len);
    dest->buffer[src_len] = '\0';  // 确保字符串终止
    return 0;
}

int main(void) {
    SafeBuffer sb = {0};
    
    if (init_buffer(&sb, 128) != 0) {
        return 1;
    }
    
    const char *msg = "Hello, safe world!";
    size_t msg_len = strlen(msg);
    
    if (copy_data(&sb, msg, msg_len) != 0) {
        safe_free(&sb);
        return 1;
    }
    
    printf("Buffer content: %s\n", sb.buffer);
    printf("Buffer size: %zu\n", sb.size);
    
    safe_free(&sb);
    return 0;
}

