#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t size;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->size = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) return;
    if (buf->data) {
        memset(buf->data, 0, buf->size);  // 清除敏感数据
        free(buf->data);
        buf->data = NULL;                  // 置空防止悬垂指针
    }
    free(buf);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <size>\n", argv[0]);
        return 1;
    }

    size_t size = strtoul(argv[1], NULL, 10);
    if (size == 0 || size > 1024 * 1024) {  // 限制大小范围
        fprintf(stderr, "Invalid size\n");
        return 1;
    }

    Buffer *buf = create_buffer(size);
    if (!buf) {
        fprintf(stderr, "Failed to allocate\n");
        return 1;
    }

    // 使用缓冲区
    snprintf(buf->data, buf->size, "Hello, world!");

    // 清理
    destroy_buffer(buf);
    // buf 不再使用，无悬垂引用
    return 0;
}

