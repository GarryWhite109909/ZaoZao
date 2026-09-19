#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_FW_VER_LEN 16
#define FW_VER_OFFSET 0x40

typedef struct {
    uint8_t header[0x80];
    uint8_t payload[256];
} firmware_image_t;

int parse_firmware_version(const uint8_t *raw_data, size_t data_len,
                           char *out_buf, size_t out_buf_size) {
    if (raw_data == NULL || out_buf == NULL) {
        return -1;
    }

    /* 模拟固件头部校验：数据长度必须大于版本偏移 */
    if (data_len < FW_VER_OFFSET + MAX_FW_VER_LEN) {
        return -2;
    }

    /* 从固件头部偏移处提取版本字符串并拷贝到输出缓冲区 */
    memcpy(out_buf, raw_data + FW_VER_OFFSET, MAX_FW_VER_LEN);  // line 18: 固定长度拷贝

    return 0;
}

int main(int argc, char *argv[]) {
    firmware_image_t fw;
    char version_buf[8];  // 小缓冲区，仅8字节

    /* 模拟从外部设备读取固件数据 */
    memset(&fw, 'A', sizeof(fw));
    fw.header[FW_VER_OFFSET] = '1';
    fw.header[FW_VER_OFFSET + 1] = '.';
    fw.header[FW_VER_OFFSET + 2] = '0';

    /* 解析版本号 */
    int ret = parse_firmware_version(fw.header, sizeof(fw.header),
                                     version_buf, sizeof(version_buf));
    if (ret != 0) {
        printf("Parse failed: %d\n", ret);
        return 1;
    }

    printf("Firmware version: %s\n", version_buf);
    return 0;
}

