#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} Buffer;

int buffer_init(Buffer *buf) {
    if (!buf) return -1;
    buf->data = (char *)malloc(BUF_SIZE);
    if (!buf->data) return -1;
    buf->len = 0;
    buf->cap = BUF_SIZE;
    return 0;
}

void buffer_free(Buffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;  // 防止悬垂指针
        buf->len = 0;
        buf->cap = 0;
    }
}

int buffer_append(Buffer *buf, const char *src, size_t src_len) {
    if (!buf || !src || !buf->data) return -1;
    
    // 检查溢出：len + src_len 不能超过 cap
    if (src_len > buf->cap - buf->len) {  // 边界检查
        return -1;
    }
    
    memcpy(buf->data + buf->len, src, src_len);
    buf->len += src_len;
    buf->data[buf->len] = '\0';  // 确保字符串终止
    return 0;
}

int main() {
    Buffer buffer;
    char input[100];
    
    if (buffer_init(&buffer) != 0) {
        fprintf(stderr, "初始化失败\n");
        return 1;
    }
    
    printf("请输入数据 (最大 %zu 字节): ", BUF_SIZE - 1);
    if (fgets(input, sizeof(input), stdin) == NULL) {
        buffer_free(&buffer);
        return 1;
    }
    
    size_t input_len = strlen(input);
    // 去除换行符
    if (input_len > 0 && input[input_len - 1] == '\n') {
        input_len--;
    }
    
    if (buffer_append(&buffer, input, input_len) != 0) {
        fprintf(stderr, "数据过长，写入失败\n");
        buffer_free(&buffer);
        return 1;
    }
    
    printf("缓冲区内容: %s\n", buffer.data);
    buffer_free(&buffer);  // 安全释放
    return 0;
}

