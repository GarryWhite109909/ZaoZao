#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(const char *input, size_t input_len) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) {
        return NULL;
    }
    buf->data = (char *)malloc(input_len + 1);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (buf) {
        free(buf->data);
        buf->data = NULL;  // line 24: 置空防止悬垂指针
        free(buf);
    }
}

int process_buffer(Buffer *buf) {
    if (!buf || !buf->data) {  // line 29: 双重检查，阻断空指针解引用
        return -1;
    }
    int sum = 0;
    for (size_t i = 0; i < buf->len; i++) {
        sum += buf->data[i];
    }
    return sum;
}

int main(void) {
    const char *msg = "hello world";
    Buffer *buf = create_buffer(msg, strlen(msg));
    if (!buf) {
        return 1;
    }
    
    int result = process_buffer(buf);
    printf("sum: %d\n", result);
    
    destroy_buffer(buf);
    // buf 已释放，但 destroy_buffer 内部已置 NULL，此处不再使用
    // 后续代码若误用 buf，由于 buf 本身仍是悬垂指针（局部变量未置空），
    // 但本函数内无后续使用，因此安全
    
    return 0;
}

