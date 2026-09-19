#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *buffer;
    size_t size;
} SafeBuffer;

SafeBuffer* create_buffer(size_t size) {
    if (size == 0 || size > MAX_BUF_SIZE) {
        return NULL;
    }
    SafeBuffer *sb = (SafeBuffer*)malloc(sizeof(SafeBuffer));
    if (!sb) {
        return NULL;
    }
    sb->buffer = (char*)malloc(size);
    if (!sb->buffer) {
        free(sb);
        return NULL;
    }
    sb->size = size;
    return sb;
}

void destroy_buffer(SafeBuffer *sb) {
    if (!sb) {
        return;
    }
    if (sb->buffer) {
        free(sb->buffer);
        sb->buffer = NULL;  // 防御：free后置NULL，防止悬垂指针
    }
    free(sb);  // 释放结构体本身
}

int write_to_buffer(SafeBuffer *sb, const char *data, size_t data_len) {
    if (!sb || !sb->buffer || !data) {
        return -1;
    }
    // 防御：边界检查，确保写入不会越界
    if (data_len >= sb->size) {
        return -1;
    }
    memcpy(sb->buffer, data, data_len);
    sb->buffer[data_len] = '\0';  // 确保安全终止
    return 0;
}

int main() {
    SafeBuffer *sb = create_buffer(128);
    if (!sb) {
        return 1;
    }
    
    const char *msg = "hello";
    if (write_to_buffer(sb, msg, strlen(msg)) == 0) {
        printf("Buffer: %s\n", sb->buffer);
    }
    
    destroy_buffer(sb);
    sb = NULL;  // 调用者侧防御：防二次释放
    return 0;
}

