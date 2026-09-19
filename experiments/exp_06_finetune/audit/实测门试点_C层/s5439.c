#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer* create_buffer(size_t size) {
    Buffer *buf = (Buffer*)malloc(sizeof(Buffer));
    if (!buf) {
        return NULL;
    }
    buf->data = (char*)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (buf) {
        if (buf->data) {
            free(buf->data);
            buf->data = NULL;  // 防御：防止悬垂指针
        }
        free(buf);
    }
}

int main() {
    Buffer *buf = create_buffer(BUFFER_SIZE);
    if (!buf) {
        fprintf(stderr, "内存分配失败\n");
        return 1;
    }

    strcpy(buf->data, "Hello, world");  // 安全：固定大小缓冲区，源字符串长度远小于BUFFER_SIZE

    printf("内容: %s\n", buf->data);

    destroy_buffer(buf);  // 安全：统一释放入口
    buf = NULL;           // 防御：调用者侧再置NULL，双保险

    return 0;
}

