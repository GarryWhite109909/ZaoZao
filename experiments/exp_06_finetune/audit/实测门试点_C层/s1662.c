#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_PATH 256
#define BASE_DIR "/var/lib/app/data"

int read_user_file(const char *user_input) {
    char filepath[MAX_PATH];
    int fd;
    char buffer[128];
    ssize_t bytes_read;

    /* 拼接用户输入到基础路径 */
    snprintf(filepath, sizeof(filepath), "%s/%s", BASE_DIR, user_input);
    
    printf("Opening file: %s\n", filepath);
    
    /* 打开文件 - 漏洞点：未验证路径是否在BASE_DIR内 */
    fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return -1;
    }
    
    /* 读取并打印文件内容 */
    bytes_read = read(fd, buffer, sizeof(buffer)-1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("File content: %s\n", buffer);
    }
    
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    return read_user_file(argv[1]);
}

