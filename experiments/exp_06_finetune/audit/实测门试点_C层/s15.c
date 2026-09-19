#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#define MAX_PKT_SIZE 1024
#define CONFIG_PATH "/var/tmp/netproto.conf"

typedef struct {
    int enabled;
    int timeout_ms;
    char filter[64];
} proto_config;

// 模拟网络协议解析的配置加载
int load_config(proto_config *cfg) {
    struct stat st;
    char buf[256];
    int fd, ret = 0;

    // 检查配置文件状态（TOCTOU窗口开始）
    if (stat(CONFIG_PATH, &st) != 0) {
        return -1;
    }
    if (st.st_size > (off_t)sizeof(buf)) {
        return -1;
    }

    // 模拟攻击者在此处替换文件（符号链接/内容替换）
    // 窗口期：stat 与 open 之间

    fd = open(CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';

    // 解析配置（简化）
    if (sscanf(buf, "enabled=%d timeout=%d filter=%63s",
               &cfg->enabled, &cfg->timeout_ms, cfg->filter) != 3) {
        return -1;
    }

    return 0;
}

// 网络协议解析入口
void parse_network_packet(const char *pkt, size_t len) {
    proto_config cfg = {0};
    if (load_config(&cfg) != 0) {
        fprintf(stderr, "Config load failed\n");
        return;
    }

    // 使用配置进行协议解析
    if (cfg.enabled && len > 0) {
        // 基于配置的过滤逻辑
        if (strstr(cfg.filter, "DROP") != NULL) {
            printf("Packet dropped per filter\n");
            return;
        }
        // 实际解析处理...
        printf("Parsed packet with timeout %d\n", cfg.timeout_ms);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <packet_hex>\n", argv[0]);
        return 1;
    }
    parse_network_packet(argv[1], strlen(argv[1]));
    return 0;
}

