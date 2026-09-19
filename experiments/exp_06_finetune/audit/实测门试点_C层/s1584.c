#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_PATH 256
#define DATA_DIR "/var/lib/app/data/"

/* 根据用户提供的文件名，读取并返回文件内容 */
int read_user_file(const char *user_input) {
    char full_path[MAX_PATH];
    int fd;
    char buffer[512];
    ssize_t bytes_read;

    /* 拼接完整路径 */
    snprintf(full_path, sizeof(full_path), "%s%s", DATA_DIR, user_input);

    /* 打开文件 */
    fd = open(full_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    /* 读取并打印文件内容 */
    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }

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

