#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_PATH 256
#define DATA_DIR "/var/lib/app/data/"

/* 从用户请求中提取文件名，拼接完整路径后读取内容 */
int read_user_file(const char *user_input) {
    char filepath[MAX_PATH];
    int fd;
    char buffer[128];
    ssize_t bytes_read;

    /* 拼接路径，未对 user_input 做任何校验 */
    snprintf(filepath, sizeof(filepath), "%s%s", DATA_DIR, user_input);

    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

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
    return read_user_file(argv[1]);
}

