#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024

/* 安全的内存复制函数：带边界检查 */
static int safe_copy(char *dest, size_t dest_size, const char *src, size_t src_len) {
    if (src == NULL || dest == NULL) {
        return -1;
    }
    if (src_len >= dest_size) {
        /* 源数据长度超过目标缓冲区，拒绝复制 */
        return -1;
    }
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';  /* 确保字符串以空字符结尾 */
    return 0;
}

/* 安全的内存释放函数：释放后立即置 NULL，防止悬垂指针 */
static void safe_free(char **ptr) {
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }
}

int process_data(const char *input, size_t input_len) {
    char *buffer = NULL;
    char *temp = NULL;
    int result = -1;

    /* 分配缓冲区 */
    buffer = (char *)malloc(MAX_BUF_SIZE);
    if (buffer == NULL) {
        return -1;
    }

    /* 分配临时缓冲区 */
    temp = (char *)malloc(MAX_BUF_SIZE / 2);
    if (temp == NULL) {
        safe_free(&buffer);
        return -1;
    }

    /* 第一层防御：检查输入长度 */
    if (input == NULL || input_len >= MAX_BUF_SIZE) {
        safe_free(&buffer);
        safe_free(&temp);
        return -1;
    }

    /* 第二层防御：使用带边界检查的复制函数 */
    if (safe_copy(buffer, MAX_BUF_SIZE, input, input_len) != 0) {
        safe_free(&buffer);
        safe_free(&temp);
        return -1;
    }

    /* 第三层防御：临时缓冲区复制前再次验证长度 */
    if (input_len >= MAX_BUF_SIZE / 2) {
        safe_free(&buffer);
        safe_free(&temp);
        return -1;
    }

    if (safe_copy(temp, MAX_BUF_SIZE / 2, buffer, input_len) != 0) {
        safe_free(&buffer);
        safe_free(&temp);
        return -1;
    }

    /* 处理数据（此处仅为演示，实际业务逻辑可替换） */
    printf("Processed data: %s\n", temp);
    result = 0;

    /* 统一释放资源，safe_free 确保置 NULL */
    safe_free(&buffer);
    safe_free(&temp);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    size_t len = strlen(argv[1]);
    return process_data(argv[1], len);
}

