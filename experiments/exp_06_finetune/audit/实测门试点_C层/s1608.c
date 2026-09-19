#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF 256

typedef struct {
    uint8_t *data;
    size_t len;
} Buffer;

// 内存池管理结构
typedef struct {
    void *pool;
    size_t pool_size;
    size_t used;
} MemPool;

static const char secret_key[] = "MySuperSecretKey123";  // line 16: 硬编码密钥

int process_packet(Buffer *input, MemPool *mp) {
    if (input == NULL || mp == NULL || input->data == NULL) {
        return -1;
    }

    // 从内存池分配临时缓冲区
    uint8_t *temp = (uint8_t *)malloc(input->len + 1);  // line 23
    if (temp == NULL) {
        return -1;
    }

    // 使用硬编码密钥进行简单异或解密
    size_t key_len = strlen(secret_key);
    for (size_t i = 0; i < input->len; i++) {
        temp[i] = input->data[i] ^ secret_key[i % key_len];  // line 29
    }
    temp[input->len] = '\0';

    // 模拟数据处理
    printf("Decrypted: %s\n", temp);
    free(temp);  // line 35

    // 更新内存池使用量（存在逻辑错误但非本漏洞重点）
    mp->used += input->len;
    return 0;
}

int main() {
    MemPool mp = {0};
    Buffer buf = {0};
    
    // 初始化内存池（简化）
    mp.pool = malloc(1024);
    mp.pool_size = 1024;
    
    // 构造输入数据
    buf.data = (uint8_t *)"encrypted_data_here";
    buf.len = strlen((char *)buf.data);
    
    process_packet(&buf, &mp);
    
    free(mp.pool);
    return 0;
}

