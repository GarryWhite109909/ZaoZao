#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_FW_VER_LEN  16
#define FW_HEADER_MAGIC 0xA5A5

typedef struct {
    uint8_t  magic[2];
    uint8_t  version_len;
    uint8_t  reserved;
    uint8_t  version[MAX_FW_VER_LEN];
} fw_header_t;

static uint8_t fw_image[128];
static uint8_t fw_version[MAX_FW_VER_LEN];

int parse_firmware_header(const uint8_t *data, size_t data_len) {
    fw_header_t hdr;

    if (data == NULL || data_len < sizeof(fw_header_t)) {
        return -1;
    }

    memcpy(&hdr, data, sizeof(fw_header_t));

    if (hdr.magic[0] != 0xA5 || hdr.magic[1] != 0x5A) {
        return -2;
    }

    /* 版本长度由外部输入控制，未校验上限 */
    memcpy(fw_version, hdr.version, hdr.version_len);

    printf("Firmware version: %s\n", fw_version);
    return 0;
}

int main(void) {
    uint8_t evil_data[32];

    memset(evil_data, 0, sizeof(evil_data));
    evil_data[0] = 0xA5;
    evil_data[1] = 0x5A;
    evil_data[2] = 32;  /* version_len 超过 fw_version 缓冲区 */

    parse_firmware_header(evil_data, sizeof(evil_data));
    return 0;
}

