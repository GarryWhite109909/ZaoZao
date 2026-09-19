#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_FW_SIZE 0x10000
#define FW_SIGNATURE 0xA5A5A5A5

typedef struct {
    uint32_t signature;
    uint32_t size;
    uint8_t data[];
} fw_header_t;

static uint8_t *fw_buffer = NULL;
static size_t fw_size = 0;

static bool validate_fw_header(fw_header_t *hdr, size_t available) {
    if (available < sizeof(fw_header_t)) {
        return false;
    }
    if (hdr->signature != FW_SIGNATURE) {
        return false;
    }
    if (hdr->size > MAX_FW_SIZE || hdr->size > available - sizeof(fw_header_t)) {
        return false;
    }
    return true;
}

static bool load_firmware(uint8_t *src, size_t src_len) {
    if (src == NULL || src_len < sizeof(fw_header_t)) {
        return false;
    }
    
    fw_header_t *hdr = (fw_header_t *)src;
    if (!validate_fw_header(hdr, src_len)) {
        return false;
    }
    
    uint8_t *new_buf = (uint8_t *)malloc(hdr->size);
    if (new_buf == NULL) {
        return false;
    }
    
    memcpy(new_buf, hdr->data, hdr->size);
    
    uint8_t *old_buf = fw_buffer;
    fw_buffer = new_buf;
    fw_size = hdr->size;
    
    if (old_buf != NULL) {
        free(old_buf);
        old_buf = NULL;
    }
    
    return true;
}

void update_firmware(uint8_t *src, size_t src_len) {
    if (src == NULL || src_len == 0) {
        return;
    }
    
    load_firmware(src, src_len);
}

int main(void) {
    uint8_t fw_data[MAX_FW_SIZE + sizeof(fw_header_t)] = {0};
    fw_header_t *hdr = (fw_header_t *)fw_data;
    hdr->signature = FW_SIGNATURE;
    hdr->size = 0x100;
    
    update_firmware(fw_data, sizeof(fw_header_t) + 0x100);
    return 0;
}

