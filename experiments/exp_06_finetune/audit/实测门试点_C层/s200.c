#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_PKT 1024

typedef struct {
    char data[MAX_PKT];
    size_t len;
} packet;

int process_packet(const char *filename) {
    FILE *fp = NULL;
    packet pkt;
    struct stat st;

    // 模拟从网络接收数据包
    memset(&pkt, 0, sizeof(pkt));
    pkt.len = 512;
    strcpy(pkt.data, "NETWORK_PAYLOAD");

    // 检查文件状态（TOCTOU窗口开始）
    if (stat(filename, &st) != 0) {
        perror("stat");
        return -1;
    }

    // 模拟网络延迟/处理间隔，扩大TOCTOU窗口
    usleep(1000);

    // 基于stat结果做出信任决策
    if (st.st_size > MAX_PKT) {
        fprintf(stderr, "File too large\n");
        return -1;
    }

    // 打开文件并写入（攻击者可在此前替换文件为符号链接）
    fp = fopen(filename, "w");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    fwrite(pkt.data, 1, pkt.len, fp);
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    return process_packet(argv[1]);
}

