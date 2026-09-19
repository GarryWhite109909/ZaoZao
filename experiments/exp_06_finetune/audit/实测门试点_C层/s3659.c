#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PAYLOAD_SIZE 1024

typedef struct {
    uint16_t length;
    char *data;
} Packet;

int parse_packet(const uint8_t *buffer, size_t buffer_size, Packet *out) {
    if (buffer_size < sizeof(uint16_t)) {
        return -1; // 输入过短，无法读取长度字段
    }

    uint16_t payload_len = (buffer[0] << 8) | buffer[1];
    // 第10行：长度字段来自网络字节序，需验证是否超过最大限制
    if (payload_len > MAX_PAYLOAD_SIZE || payload_len > buffer_size - sizeof(uint16_t)) {
        return -1; // 长度超限或超出实际缓冲区，拒绝解析
    }

    out->data = (char *)malloc(payload_len + 1);
    if (out->data == NULL) {
        return -1; // 内存分配失败
    }

    // 第17行：payload_len 已通过双重校验，此处拷贝不会越界
    memcpy(out->data, buffer + sizeof(uint16_t), payload_len);
    out->data[payload_len] = '\0'; // 确保字符串以空字符结尾
    out->length = payload_len;
    return 0;
}

void process_packet(const uint8_t *raw, size_t raw_len) {
    Packet pkt;
    pkt.data = NULL; // 第25行：初始化指针，便于后续安全释放

    if (parse_packet(raw, raw_len, &pkt) != 0) {
        return; // 解析失败，不进入释放流程（data仍为NULL）
    }

    // 此处模拟业务处理，仅打印长度
    printf("Received packet, length: %u\n", pkt.length);

    free(pkt.data); // 第33行：正常路径释放
    pkt.data = NULL; // 第34行：释放后置NULL，防止悬垂指针
}

int main() {
    uint8_t test_data[] = {0x00, 0x04, 't', 'e', 's', 't'};
    process_packet(test_data, sizeof(test_data));
    return 0;
}

