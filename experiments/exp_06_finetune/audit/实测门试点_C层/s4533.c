#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void buffer_free(Buffer *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;  // line 10: 置NULL防止悬垂指针
    buf->len = 0;
}

static int process_buffer(Buffer *buf, const char *input) {
    if (!buf || !input) return -1;
    
    // line 16: 使用前检查data是否有效
    if (!buf->data) return -1;
    
    size_t input_len = strlen(input);
    if (input_len >= buf->len) return -1;  // line 19: 边界检查
    
    // line 21: 在持有data期间不释放，安全使用
    memcpy(buf->data, input, input_len + 1);
    return 0;
}

int main(void) {
    Buffer buf;
    buf.data = (char *)malloc(64);
    if (!buf.data) return 1;
    buf.len = 64;
    
    // line 30: 先使用
    if (process_buffer(&buf, "hello") != 0) {
        buffer_free(&buf);
        return 1;
    }
    printf("Data: %s\n", buf.data);  // line 34: 此时data仍有效
    
    // line 36: 释放并置NULL
    buffer_free(&buf);
    
    // line 38: 释放后再使用会被防御拦截
    if (process_buffer(&buf, "world") != 0) {
        printf("Safe: buffer is freed\n");
    }
    
    return 0;
}

