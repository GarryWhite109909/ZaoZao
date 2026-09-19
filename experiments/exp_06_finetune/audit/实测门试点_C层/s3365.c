#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void safe_free(Buffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;  // 防御：置NULL防止悬垂指针
        buf->len = 0;
    }
}

static Buffer *create_buffer(const char *input) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    
    size_t input_len = strlen(input);
    if (input_len >= MAX_BUF) {  // 防御：输入长度边界检查
        free(buf);
        return NULL;
    }
    
    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    strcpy(buf->data, input);
    buf->len = input_len;
    return buf;
}

static int process_buffer(Buffer *buf) {
    if (!buf || !buf->data) return -1;
    
    // 模拟处理：读取缓冲区内容
    printf("Processing: %s\n", buf->data);
    
    safe_free(buf);  // 释放后置NULL
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    Buffer *buf = create_buffer(argv[1]);
    if (!buf) {
        fprintf(stderr, "Failed to create buffer\n");
        return 1;
    }
    
    if (process_buffer(buf) == 0) {
        // 再次访问已释放但被置NULL的指针
        if (buf->data == NULL) {
            printf("Buffer safely freed\n");
        }
    }
    
    // 不重复free，因为safe_free已置NULL
    return 0;
}

