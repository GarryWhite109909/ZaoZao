#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024

typedef struct {
    char *data;
    size_t len;
} Buffer;

int safe_buffer_free(Buffer *buf) {
    if (buf == NULL) {
        return -1;
    }
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;  // 防止悬空指针
    }
    buf->len = 0;
    return 0;
}

int process_data(const char *input, size_t input_len) {
    Buffer buf;
    buf.data = NULL;
    buf.len = 0;

    // 边界检查：确保输入长度在合理范围内
    if (input == NULL || input_len == 0 || input_len > MAX_BUF_SIZE) {
        fprintf(stderr, "Invalid input length: %zu\n", input_len);
        return -1;
    }

    // 分配内存，并检查分配是否成功
    buf.data = (char *)malloc(input_len + 1);
    if (buf.data == NULL) {
        perror("malloc failed");
        return -1;
    }

    // 使用 memcpy 避免字符串终止符问题，并显式设置终止符
    memcpy(buf.data, input, input_len);
    buf.data[input_len] = '\0';
    buf.len = input_len;

    // 模拟数据处理
    printf("Processed: %s\n", buf.data);

    // 安全释放：即使前面有错误分支，这里也确保释放
    return safe_buffer_free(&buf);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    size_t len = strlen(argv[1]);
    if (len > MAX_BUF_SIZE) {
        fprintf(stderr, "Input too long\n");
        return 1;
    }

    return process_data(argv[1], len);
}

