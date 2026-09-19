#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_PKT 1024
#define CONFIG_PATH "/var/tmp/proto.conf"

/* 网络协议解析：接收客户端数据包，更新本地配置文件 */
int process_packet(int client_fd) {
    char buf[MAX_PKT];
    int n = recv(client_fd, buf, sizeof(buf), 0);
    if (n <= 0) return -1;
    buf[n] = '\0';

    /* 检查配置文件是否存在（TOCTOU 窗口开始） */
    struct stat st;
    if (stat(CONFIG_PATH, &st) != 0) {
        /* 不存在则创建 */
        int fd = open(CONFIG_PATH, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) return -1;
        write(fd, "default\n", 8);
        close(fd);
    }

    /* 重新打开文件并追加解析结果（攻击者可在 stat 和 open 之间替换文件） */
    int fd = open(CONFIG_PATH, O_WRONLY | O_APPEND);
    if (fd < 0) return -1;

    /* 简单协议：写入 "key=value" 行 */
    char line[128];
    snprintf(line, sizeof(line), "client_data=%s\n", buf);
    write(fd, line, strlen(line));
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(srv_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv_fd, 5);

    while (1) {
        int client_fd = accept(srv_fd, NULL, NULL);
        if (client_fd >= 0) {
            process_packet(client_fd);
            close(client_fd);
        }
    }
    return 0;
}

