#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void safe_free(Buffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;  // line 10: 置NULL防止悬垂
        buf->len = 0;
    }
}

static Buffer *create_buffer(const char *input, size_t input_len) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    
    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        free(buf);  // line 19: 释放已分配的结构体
        return NULL;
    }
    
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;
    return buf;
}

static int process_buffer(Buffer *buf) {
    if (!buf || !buf->data) return -1;  // line 27: 空指针检查
    
    // 模拟处理逻辑
    size_t total = 0;
    for (size_t i = 0; i < buf->len; i++) {
        if (buf->data[i] == 'a') total++;
    }
    return (int)total;
}

int main(void) {
    const char *user_input = "hello world";
    size_t input_len = strlen(user_input);
    
    Buffer *buf = create_buffer(user_input, input_len);
    if (!buf) return 1;
    
    int result = process_buffer(buf);
    printf("Count: %d\n", result);
    
    safe_free(buf);  // line 45: 释放并置NULL
    free(buf);       // line 46: 释放结构体本身
    
    // 后续不再使用buf
    return 0;
}

