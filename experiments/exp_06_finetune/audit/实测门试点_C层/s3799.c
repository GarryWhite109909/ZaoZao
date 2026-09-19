#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) {
        return NULL;
    }
    buf->data = (char *)malloc(size);
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
            buf->data = NULL;  // 防止悬垂指针
        }
        free(buf);
        buf = NULL;  // 局部指针置空，防御性编程
    }
}

int write_to_buffer(Buffer *buf, const char *src, size_t src_len) {
    if (!buf || !buf->data || !src) {
        return -1;
    }
    if (src_len > buf->len) {
        return -1;  // 边界检查，防止缓冲区溢出
    }
    memcpy(buf->data, src, src_len);
    return 0;
}

int main() {
    Buffer *buf = create_buffer(MAX_BUF_SIZE);
    if (!buf) {
        return -1;
    }

    char input[512];
    printf("Enter data (max 511 chars): ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        destroy_buffer(buf);
        return -1;
    }

    size_t input_len = strlen(input);
    if (input_len > 0 && input[input_len - 1] == '\n') {
        input[input_len - 1] = '\0';
        input_len--;
    }

    // 安全写入：src_len 受输入长度限制，且 write_to_buffer 内部有边界检查
    if (write_to_buffer(buf, input, input_len) != 0) {
        printf("Write failed: input too large\n");
        destroy_buffer(buf);
        return -1;
    }

    printf("Buffer content: %s\n", (char *)buf->data);
    destroy_buffer(buf);
    return 0;
}

