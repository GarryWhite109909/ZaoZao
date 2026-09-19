#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_PATH 256
#define MAX_BUF 1024

/* 处理用户请求，读取指定文件内容 */
int handle_request(const char *user_input) {
    char filepath[MAX_PATH];
    char buffer[MAX_BUF];
    int fd;
    ssize_t bytes_read;

    /* 构造文件路径 */
    snprintf(filepath, sizeof(filepath), "/var/data/%s", user_input);

    /* 打开文件 */
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    /* 读取文件内容并输出 */
    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("read");
        close(fd);
        return -1;
    }
    buffer[bytes_read] = '\0';
    printf("File content: %s\n", buffer);

    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    return handle_request(argv[1]);
}

