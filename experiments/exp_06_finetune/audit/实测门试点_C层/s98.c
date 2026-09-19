#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_LEN 512
#define HDR_LEN 8

/* 网络协议帧：header[8] + payload */
typedef struct {
    uint8_t buf[MAX_PKT_LEN];
    size_t len;
} pkt_t;

/* 解析协议头，返回payload长度（含校验） */
static size_t parse_header(const uint8_t *hdr) {
    uint16_t payload_len = (hdr[4] << 8) | hdr[5];
    /* 恶意帧可令payload_len=65535，但buf只有512 */
    return payload_len;
}

/* 跨函数调用：从socket读取并处理一帧 */
int process_packet(int sockfd) {
    pkt_t pkt;
    ssize_t n = recv(sockfd, pkt.buf, MAX_PKT_LEN, 0);
    if (n < HDR_LEN) return -1;

    size_t payload_len = parse_header(pkt.buf);
    /* 栈上局部变量，用于拷贝payload */
    uint8_t payload[64];

    /* 漏洞：未校验payload_len <= sizeof(payload) */
    memcpy(payload, pkt.buf + HDR_LEN, payload_len);  // line 26

    /* 模拟后续处理 */
    for (size_t i = 0; i < payload_len; i++) {
        payload[i] ^= 0x5A;
    }
    return 0;
}

/* 主循环：简化网络服务 */
int main(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 1;
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return 1;
    if (listen(sockfd, 5) < 0) return 1;
    
    int client = accept(sockfd, NULL, NULL);
    if (client < 0) return 1;
    
    process_packet(client);
    close(client);
    close(sockfd);
    return 0;
}

