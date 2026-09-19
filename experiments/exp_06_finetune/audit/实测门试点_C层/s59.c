#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 256

// 模拟网络协议包解析：读取长度字段，然后拷贝数据
int parse_packet(const uint8_t *buffer, size_t buffer_len) {
    uint16_t data_len;
    uint8_t data_buf[64];

    if (buffer_len < 2) {
        return -1;
    }

    // 从网络字节序读取数据长度（前2字节）
    data_len = (buffer[0] << 8) | buffer[1];

    // 检查长度是否超过剩余缓冲区（防御存在，但未检查目标数组大小）
    if (data_len > buffer_len - 2) {
        return -1;
    }

    // 漏洞：data_len 最大可达 65535，但 data_buf 只有 64 字节
    memcpy(data_buf, buffer + 2, data_len);

    // 模拟后续处理
    printf("Received %u bytes of data\n", data_len);
    return 0;
}

int main() {
    // 构造恶意数据包：长度字段为 100，实际数据 100 字节
    uint8_t malicious_packet[MAX_PACKET_SIZE];
    malicious_packet[0] = 0x00;
    malicious_packet[1] = 0x64;  // 100

    // 填充数据
    memset(malicious_packet + 2, 'A', 100);

    parse_packet(malicious_packet, 102);

    return 0;
}

