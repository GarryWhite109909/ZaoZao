#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

typedef struct {
    uint32_t length;
    char *data;
} Packet;

int parse_packet(int fd, Packet *pkt) {
    // line 10: 读取长度字段
    if (read(fd, &pkt->length, sizeof(pkt->length)) != sizeof(pkt->length)) {
        return -1;
    }
    // line 13: 边界检查：长度上限限制为 64KB，防止整数溢出和资源耗尽
    if (pkt->length > 65536) {
        return -2;
    }
    pkt->data = (char *)malloc(pkt->length);
    if (!pkt->data) {
        return -3;
    }
    // line 20: 读取数据体
    ssize_t n = read(fd, pkt->data, pkt->length);
    if (n != pkt->length) {
        free(pkt->data);
        pkt->data = NULL;  // line 24: free后置NULL，防止悬垂指针
        return -4;
    }
    return 0;
}

void process_packet(int fd) {
    Packet pkt = {0, NULL};  // line 30: 初始化结构体，避免未初始化数据
    if (parse_packet(fd, &pkt) == 0) {
        // 处理数据
        printf("Received %u bytes\n", pkt.length);
    }
    // line 35: 统一释放路径，即使parse失败也安全
    if (pkt.data) {
        free(pkt.data);
        pkt.data = NULL;
    }
}

int main(void) {
    int fd = dup(STDIN_FILENO);
    if (fd < 0) return 1;
    process_packet(fd);
    close(fd);
    return 0;
}

