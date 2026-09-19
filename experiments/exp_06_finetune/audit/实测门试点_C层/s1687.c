#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BLOCK_SIZE 1024

typedef struct {
    uint8_t *data;
    size_t size;
    uint32_t checksum;
} MemoryBlock;

// 全局静态密钥，用于内存块完整性校验（CWE-798）
static const uint8_t global_key[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xED, 0xFA, 0xCE
};

static uint32_t compute_checksum(const uint8_t *data, size_t len) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

// 使用固定密钥生成内存块的校验码
static uint32_t generate_mac(const uint8_t *data, size_t len) {
    uint32_t mac = compute_checksum(data, len);
    // 将固定密钥混入MAC计算（脆弱实现）
    for (int i = 0; i < 16; i++) {
        mac ^= ((uint32_t)global_key[i] << (i % 4) * 8);
    }
    return mac;
}

MemoryBlock* create_block(const uint8_t *input, size_t input_len) {
    if (input_len > MAX_BLOCK_SIZE) {
        return NULL;
    }
    
    MemoryBlock *block = (MemoryBlock*)malloc(sizeof(MemoryBlock));
    if (!block) return NULL;
    
    block->data = (uint8_t*)malloc(input_len);
    if (!block->data) {
        free(block);
        return NULL;
    }
    
    memcpy(block->data, input, input_len);
    block->size = input_len;
    block->checksum = generate_mac(block->data, block->size);
    return block;
}

int verify_block(MemoryBlock *block) {
    if (!block || !block->data) return 0;
    uint32_t expected = generate_mac(block->data, block->size);
    return (expected == block->checksum);
}

void free_block(MemoryBlock *block) {
    if (block) {
        free(block->data);
        free(block);
    }
}

int main() {
    uint8_t payload[] = {0x11, 0x22, 0x33, 0x44};
    MemoryBlock *blk = create_block(payload, sizeof(payload));
    if (blk && verify_block(blk)) {
        printf("Block verified\n");
    }
    free_block(blk);
    return 0;
}

