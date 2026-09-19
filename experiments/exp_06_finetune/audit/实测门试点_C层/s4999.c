#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 64

typedef struct {
    char *data;
    size_t size;
} Buffer;

Buffer* create_buffer(size_t size) {
    Buffer *buf = (Buffer*)malloc(sizeof(Buffer));
    if (!buf) {
        return NULL;
    }
    buf->data = (char*)malloc(size);
    if (!buf->data) {
        free(buf);          // line 20: 释放结构体，防止泄漏
        return NULL;
    }
    buf->size = size;
    return buf;
}

void safe_free(Buffer *buf) {
    if (buf) {
        if (buf->data) {
            free(buf->data);    // line 28: 释放内部数据
            buf->data = NULL;   // line 29: 置NULL防止悬垂指针
        }
        free(buf);              // line 31: 释放结构体
        buf = NULL;             // line 32: 置NULL（仅影响局部）
    }
}

int process_data(Buffer *buf) {
    if (!buf || !buf->data) {
        return -1;
    }
    // 模拟数据处理
    for (size_t i = 0; i < buf->size; i++) {
        buf->data[i] = (char)(i % 128);
    }
    return 0;
}

int main() {
    Buffer *my_buf = create_buffer(MAX_BUF_SIZE);
    if (!my_buf) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }

    if (process_data(my_buf) != 0) {
        safe_free(my_buf);
        return 1;
    }

    safe_free(my_buf);   // line 55: 唯一释放点，无双free
    return 0;
}

