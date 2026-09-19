#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024
#define MAX_FIELD_LEN 64

typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len;
} Packet;

int parse_packet_header(const uint8_t *buf, size_t buf_len, char *out_field, size_t out_size) {
    if (buf == NULL || out_field == NULL) {
        return -1;
    }

    // line 10: 检查缓冲区长度是否足够容纳头部字段
    if (buf_len < 2) {
        return -1;
    }

    // line 12: 提取字段长度（假设头2字节为大端序长度字段）
    uint16_t field_len = (buf[0] << 8) | buf[1];
    
    // line 15: 边界检查：字段长度必须小于等于缓冲区剩余空间
    if (field_len > buf_len - 2) {
        return -1;
    }

    // line 18: 边界检查：字段长度必须小于目标缓冲区大小
    if (field_len >= out_size) {
        return -1;
    }

    // line 21: 安全拷贝，使用memcpy前已确认field_len < out_size
    memcpy(out_field, buf + 2, field_len);
    out_field[field_len] = '\0';  // line 23: 手动添加字符串终止符

    return 0;
}

int process_packet(const Packet *pkt) {
    if (pkt == NULL) {
        return -1;
    }

    char field[MAX_FIELD_LEN];
    
    // line 32: 调用解析函数，传入目标缓冲区及其大小
    if (parse_packet_header(pkt->data, pkt->len, field, sizeof(field)) != 0) {
        return -1;
    }

    printf("Parsed field: %s\n", field);
    return 0;
}

int main() {
    Packet pkt = {0};
    
    // 模拟网络接收数据
    uint8_t raw_data[] = {0x00, 0x05, 'H', 'e', 'l', 'l', 'o'};
    pkt.len = sizeof(raw_data);
    memcpy(pkt.data, raw_data, pkt.len);

    return process_packet(&pkt);
}

