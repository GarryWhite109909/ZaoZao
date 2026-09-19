#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_PATH 256
#define BASE_DIR "/var/lib/app/data/"

/* API: 根据用户提供的文件名返回文件内容 */
int read_user_file(const char *user_input) {
    char fullpath[MAX_PATH];
    char buffer[128];
    int fd, n;

    /* 拼接路径，未做任何规范化或验证 */
    snprintf(fullpath, sizeof(fullpath), "%s%s", BASE_DIR, user_input);
    
    fd = open(fullpath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    n = read(fd, buffer, sizeof(buffer) - 1);
    if (n < 0) {
        perror("read");
        close(fd);
        return -1;
    }
    buffer[n] = '\0';
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

