#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF_SIZE 256
#define SAFE_PATTERN "0x%02x"

/* 安全内存清理函数：使用 volatile 防止编译器优化 */
static void secure_wipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0x00;
    }
}

/* 从安全存储获取敏感数据（模拟：实际应从HSM或密钥库读取） */
static int fetch_credential(char *out, size_t out_size) {
    /* 绝不硬编码密钥；从环境变量或安全存储读取 */
    const char *env_val = getenv("DB_CREDENTIAL");
    if (env_val == NULL || strlen(env_val) >= out_size) {
        return -1;
    }
    strncpy(out, env_val, out_size - 1);
    out[out_size - 1] = '\0';
    return 0;
}

int main(void) {
    char credential[MAX_BUF_SIZE] = {0};
    char *heap_copy = NULL;

    /* 1. 从外部安全源获取凭据，而非硬编码 */
    if (fetch_credential(credential, sizeof(credential)) != 0) {
        fprintf(stderr, "Failed to retrieve credential\n");
        return EXIT_FAILURE;
    }

    /* 2. 堆上分配，用于演示完整生命周期管理 */
    heap_copy = (char *)malloc(strlen(credential) + 1);
    if (heap_copy == NULL) {
        return EXIT_FAILURE;
    }
    strcpy(heap_copy, credential);

    /* 3. 使用凭据（此处模拟数据库连接） */
    printf("Connecting with credential length: %zu\n", strlen(heap_copy));

    /* 4. 使用完毕立即安全擦除所有内存中的敏感数据 */
    secure_wipe(heap_copy, strlen(heap_copy));
    free(heap_copy);
    heap_copy = NULL;

    secure_wipe(credential, sizeof(credential));
    
    printf("Credential securely wiped and freed\n");
    return EXIT_SUCCESS;
}

