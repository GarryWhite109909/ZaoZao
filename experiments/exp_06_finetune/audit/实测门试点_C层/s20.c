#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_PAYLOAD_LEN 128
#define SECTOR_SIZE 512

typedef struct {
    uint8_t *data;
    uint32_t len;
} packet_t;

static int process_packet(packet_t *pkt, uint8_t *out_buf, uint32_t out_len) {
    if (pkt->len > MAX_PAYLOAD_LEN) {
        return -1;
    }
    // 模拟解压：实际固件中此处会根据数据头计算解压后大小
    uint32_t decompressed_len = pkt->data[0] * 256 + pkt->data[1];
    if (decompressed_len > out_len) {
        return -2;
    }
    // 漏洞点：memcpy 长度取自解压后大小，但未检查 decompressed_len 与 pkt->len 的关系
    memcpy(out_buf, pkt->data + 2, decompressed_len);
    return 0;
}

static int handle_radio_frame(uint8_t *rx_buf, uint32_t rx_len) {
    packet_t pkt;
    uint8_t *output = (uint8_t *)malloc(SECTOR_SIZE);
    if (!output) return -1;

    pkt.data = rx_buf;
    pkt.len = rx_len;

    int ret = process_packet(&pkt, output, SECTOR_SIZE);
    if (ret != 0) {
        free(output);
        return ret;
    }

    // 模拟后续处理
    uint32_t crc = 0;
    for (uint32_t i = 0; i < SECTOR_SIZE; i++) {
        crc += output[i];
    }
    printf("CRC: %u\n", crc);

    free(output);
    return 0;
}

int main() {
    // 模拟从无线接收到的数据帧（前2字节为解压后长度声明）
    uint8_t frame[MAX_PAYLOAD_LEN + 2];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x01;  // 高字节：声明解压后 0x0100 = 256 字节
    frame[1] = 0x00;  // 低字节
    // 实际数据只有 2 字节，但解压后长度为 256

    handle_radio_frame(frame, 2);
    return 0;
}

