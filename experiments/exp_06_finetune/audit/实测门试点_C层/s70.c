#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void process_buffer(Buffer *buf, const char *input, size_t input_len) {
    if (input_len > MAX_BUF - 1) {
        input_len = MAX_BUF - 1;
    }
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;
}

static void free_buffer(Buffer *buf) {
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->len = 0;
}

static void handle_request(const char *user_input, size_t user_len) {
    Buffer buf;
    buf.data = (char *)malloc(MAX_BUF);
    if (!buf.data) {
        return;
    }
    buf.len = 0;

    process_buffer(&buf, user_input, user_len);

    /* 模拟业务处理 */
    printf("Processed: %s\n", buf.data);

    free_buffer(&buf);
    /* 漏洞：free 后未重置 buf.data 指针（free_buffer 已置 NULL，但此处直接访问） */
    printf("Debug: %s\n", buf.data);  // line 35: UAF - 使用已释放的 buf.data
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    handle_request(argv[1], strlen(argv[1]));
    return 0;
}

