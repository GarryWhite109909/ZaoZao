#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void buffer_free(Buffer *buf) {
    if (buf == NULL) return;
    free(buf->data);
    buf->data = NULL;  // line 10: 释放后立即置NULL，防止悬垂指针
    buf->len = 0;
}

static int buffer_resize(Buffer *buf, size_t new_len) {
    if (buf == NULL || new_len == 0) return -1;
    char *new_data = (char *)realloc(buf->data, new_len);
    if (new_data == NULL) return -1;  // line 16: realloc失败，原指针仍有效
    buf->data = new_data;
    buf->len = new_len;
    return 0;
}

static void process_buffer(Buffer *buf) {
    if (buf == NULL || buf->data == NULL) return;  // line 21: 入口检查
    printf("Processing %zu bytes: %.*s\n", buf->len, (int)buf->len, buf->data);
}

int main(void) {
    Buffer buf = {0};
    
    if (buffer_resize(&buf, 64) != 0) {
        fprintf(stderr, "Allocation failed\n");
        return 1;
    }
    strcpy(buf.data, "Hello, UAF defense demo");
    
    process_buffer(&buf);  // 正常使用
    
    buffer_free(&buf);     // line 36: 释放并置NULL
    
    // 后续所有使用都经过NULL检查
    process_buffer(&buf);  // line 39: 安全，buf.data为NULL，函数直接返回
    
    buffer_free(&buf);     // line 41: 双重释放防御，buf.data为NULL，free(NULL)安全
    
    return 0;
}

