#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_PKT_SIZE 256
#define HEADER_LEN 8

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t seq;
} pkt_header_t;

int parse_packet(const uint8_t *buf, size_t buf_len) {
    pkt_header_t hdr;
    uint8_t payload[64];
    
    if (buf_len < HEADER_LEN) {
        return -1;
    }
    
    memcpy(&hdr, buf, HEADER_LEN);
    
    /* 网络字节序转换 */
    hdr.type = ntohs(hdr.type);
    hdr.len = ntohs(hdr.len);
    hdr.seq = ntohl(hdr.seq);
    
    /* 检查长度字段是否与剩余数据匹配 */
    if (hdr.len > buf_len - HEADER_LEN) {
        return -1;
    }
    
    /* 漏洞：未检查 hdr.len 是否超过 payload 缓冲区大小 */
    memcpy(payload, buf + HEADER_LEN, hdr.len);
    
    /* 模拟处理 */
    printf("Packet type=%u len=%u seq=%u\n", hdr.type, hdr.len, hdr.seq);
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t packet[MAX_PKT_SIZE];
    
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    size_t n = fread(packet, 1, sizeof(packet), fp);
    fclose(fp);
    
    if (n > 0) {
        parse_packet(packet, n);
    }
    
    return 0;
}

