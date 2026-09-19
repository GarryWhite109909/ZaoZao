#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *data;
    size_t size;
} Buffer;

static void safe_free(Buffer *buf) {
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;  // line 13: 置NULL防止悬垂指针
    }
    buf->size = 0;
}

static int process_buffer(Buffer *buf, const char *input) {
    size_t input_len = strlen(input);
    
    if (input_len >= buf->size) {  // line 19: 边界检查，防止越界写入
        fprintf(stderr, "Input too large\n");
        return -1;
    }
    
    memcpy(buf->data, input, input_len + 1);  // line 23: 安全拷贝，包含终止符
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    Buffer buf = {0};
    buf.data = (char *)malloc(MAX_BUF_SIZE);  // line 33: 分配固定大小内存
    if (buf.data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    buf.size = MAX_BUF_SIZE;
    
    if (process_buffer(&buf, argv[1]) != 0) {
        safe_free(&buf);  // line 41: 失败路径也释放内存
        return 1;
    }
    
    printf("Processed: %s\n", buf.data);
    safe_free(&buf);  // line 45: 正常路径释放并置NULL
    return 0;
}

