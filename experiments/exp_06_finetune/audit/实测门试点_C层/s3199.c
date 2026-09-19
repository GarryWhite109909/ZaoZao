#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define FW_MAX_SIZE 4096
#define FW_HEADER_SIZE 8

typedef struct {
    uint8_t data[FW_MAX_SIZE];
    size_t len;
} fw_buffer_t;

static int validate_fw_header(const uint8_t *hdr, size_t hdr_len) {
    if (hdr_len < FW_HEADER_SIZE) {
        return -1;
    }
    /* 固件头部魔数校验 */
    if (hdr[0] != 0xAA || hdr[1] != 0x55) {
        return -1;
    }
    /* 固件长度字段（小端序） */
    uint16_t fw_len = (uint16_t)(hdr[2] | (hdr[3] << 8));
    if (fw_len == 0 || fw_len > FW_MAX_SIZE) {
        return -1;
    }
    return (int)fw_len;
}

static int copy_fw_payload(uint8_t *dst, size_t dst_cap,
                           const uint8_t *src, size_t src_len) {
    if (dst == NULL || src == NULL || src_len > dst_cap) {
        return -1;
    }
    memcpy(dst, src, src_len);
    return 0;
}

int process_firmware(const uint8_t *fw_data, size_t fw_data_len,
                     fw_buffer_t *out) {
    if (fw_data == NULL || out == NULL || fw_data_len < FW_HEADER_SIZE) {
        return -1;
    }

    int payload_len = validate_fw_header(fw_data, fw_data_len);
    if (payload_len <= 0) {
        return -1;
    }

    /* 确保 payload 没有超出输入缓冲区 */
    if ((size_t)payload_len > fw_data_len - FW_HEADER_SIZE) {
        return -1;
    }

    size_t copy_len = (size_t)payload_len;
    if (copy_len > sizeof(out->data)) {
        return -1;
    }

    if (copy_fw_payload(out->data, sizeof(out->data),
                        fw_data + FW_HEADER_SIZE, copy_len) != 0) {
        return -1;
    }

    out->len = copy_len;
    return 0;
}

int main(void) {
    uint8_t fw[] = {0xAA, 0x55, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04,
                    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    fw_buffer_t result = {0};

    if (process_firmware(fw, sizeof(fw), &result) == 0) {
        printf("Firmware processed: %zu bytes\n", result.len);
    } else {
        printf("Firmware rejected\n");
    }
    return 0;
}

