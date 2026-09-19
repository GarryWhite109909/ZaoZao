#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_PKT_SIZE 1024
#define CONFIG_PATH "/tmp/net_config"

typedef struct {
    char data[MAX_PKT_SIZE];
    size_t len;
} packet_t;

/* 读取配置文件中的最大连接数 */
int get_max_connections(const char *path) {
    struct stat st;
    char buf[64];
    int fd, max_conn = 10;
    
    /* 检查文件是否存在且是普通文件 */
    if (lstat(path, &st) == -1) {
        perror("lstat");
        return max_conn;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Not a regular file\n");
        return max_conn;
    }
    
    /* 打开并读取 */
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return max_conn;
    }
    
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    
    if (n > 0) {
        buf[n] = '\0';
        int val = atoi(buf);
        if (val > 0)
            max_conn = val;
    }
    return max_conn;
}

/* 网络协议解析入口 */
int parse_network_packet(packet_t *pkt) {
    if (!pkt || pkt->len > MAX_PKT_SIZE)
        return -1;
    
    /* 根据配置决定是否接受大负载 */
    int max_conn = get_max_connections(CONFIG_PATH);
    if (max_conn > 50) {
        /* 高配置：允许更大数据包 */
        if (pkt->len > MAX_PKT_SIZE * 2)
            return -1;
    } else {
        if (pkt->len > MAX_PKT_SIZE)
            return -1;
    }
    
    /* 处理数据... */
    printf("Processing packet of len %zu\n", pkt->len);
    return 0;
}

int main(int argc, char *argv[]) {
    packet_t pkt = {0};
    pkt.len = 800;
    
    /* 模拟网络收包 */
    if (argc > 1)
        pkt.len = atoi(argv[1]);
    
    return parse_network_packet(&pkt);
}

