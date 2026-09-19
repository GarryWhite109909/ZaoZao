#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;  // line 22: 防止悬垂指针
    free(buf);
    // buf 本身不再使用，但调用方需自行将 buf 置 NULL
}

int main() {
    Buffer *b = create_buffer(64);
    if (!b) return 1;

    strcpy(b->data, "hello");
    printf("%s\n", b->data);

    destroy_buffer(b);
    b = NULL;  // line 34: 调用方将指针置 NULL，避免后续误用

    // 以下代码不会执行，但展示防御后的安全访问模式
    if (b != NULL) {
        printf("%s\n", b->data);  // 不可达，但若 b 未置 NULL 则此处会触发 UAF
    }

    return 0;
}

