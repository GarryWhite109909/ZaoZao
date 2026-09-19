#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 128

static char *global_buffer = NULL;

/* 安全的内存分配器：分配后立即绑定到全局指针 */
static int init_global_buffer(void) {
    if (global_buffer != NULL) {
        return 0;  /* 已初始化，避免重复分配 */
    }
    global_buffer = (char *)malloc(MAX_BUF_SIZE);
    if (global_buffer == NULL) {
        return -1;  /* 分配失败 */
    }
    memset(global_buffer, 0, MAX_BUF_SIZE);
    return 0;
}

/* 安全的释放函数：释放后置NULL，防止悬垂指针 */
static void cleanup_global_buffer(void) {
    if (global_buffer != NULL) {
        free(global_buffer);
        global_buffer = NULL;  /* 关键：置NULL防止double-free或use-after-free */
    }
}

/* 写入数据到全局缓冲区，带边界检查 */
static int write_to_buffer(const char *input, size_t input_len) {
    if (input == NULL || global_buffer == NULL) {
        return -1;
    }
    if (input_len >= MAX_BUF_SIZE) {
        return -2;  /* 拒绝超长输入 */
    }
    memcpy(global_buffer, input, input_len);
    global_buffer[input_len] = '\0';  /* 确保字符串终止 */
    return 0;
}

int main(void) {
    const char *test_data = "Hello, Secure World!";
    size_t data_len = strlen(test_data);

    if (init_global_buffer() != 0) {
        fprintf(stderr, "Buffer init failed\n");
        return 1;
    }

    if (write_to_buffer(test_data, data_len) != 0) {
        fprintf(stderr, "Write failed\n");
        cleanup_global_buffer();
        return 1;
    }

    printf("Buffer content: %s\n", global_buffer);
    cleanup_global_buffer();
    return 0;
}

