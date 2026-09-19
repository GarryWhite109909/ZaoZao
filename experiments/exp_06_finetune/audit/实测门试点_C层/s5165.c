#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buffer;
    size_t size;
} SafeBuffer;

// 初始化缓冲区，分配 size 字节
int init_buffer(SafeBuffer *sb, size_t size) {
    if (sb == NULL || size == 0) {
        return -1;
    }
    sb->buffer = (char *)malloc(size);
    if (sb->buffer == NULL) {
        return -1;
    }
    sb->size = size;
    memset(sb->buffer, 0, size);
    return 0;
}

// 将 src 复制到缓冲区，限制长度不超过缓冲区大小
int copy_to_buffer(SafeBuffer *sb, const char *src, size_t src_len) {
    if (sb == NULL || src == NULL || sb->buffer == NULL) {
        return -1;
    }
    // 边界检查：确保复制长度不超过缓冲区容量
    if (src_len >= sb->size) {
        return -1;
    }
    memcpy(sb->buffer, src, src_len);
    sb->buffer[src_len] = '\0';  // 确保以空字符结尾
    return 0;
}

// 释放缓冲区并置空指针
void free_buffer(SafeBuffer *sb) {
    if (sb == NULL) {
        return;
    }
    if (sb->buffer != NULL) {
        free(sb->buffer);
        sb->buffer = NULL;  // 防止悬空指针
    }
    sb->size = 0;
}

int main() {
    SafeBuffer sb;
    const char *data = "Hello, secure world!";
    size_t data_len = strlen(data);

    // 初始化缓冲区，大小为 32 字节，足够容纳 data
    if (init_buffer(&sb, 32) != 0) {
        fprintf(stderr, "Buffer initialization failed\n");
        return 1;
    }

    // 复制数据，长度检查确保不会溢出
    if (copy_to_buffer(&sb, data, data_len) != 0) {
        fprintf(stderr, "Copy failed\n");
        free_buffer(&sb);
        return 1;
    }

    printf("Buffer content: %s\n", sb.buffer);

    // 释放资源
    free_buffer(&sb);
    return 0;
}

