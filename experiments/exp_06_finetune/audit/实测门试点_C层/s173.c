#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_BUF 128

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    char *data = NULL;
    int fd = -1;
    ssize_t nread;
    struct stat st;

    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* 获取文件大小 */
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    /* 分配缓冲区 */
    data = (char *)malloc(MAX_BUF);
    if (data == NULL) {
        perror("malloc");
        close(fd);
        return 1;
    }

    /* 读取文件内容 */
    nread = read(fd, data, MAX_BUF);
    if (nread < 0) {
        perror("read");
        free(data);
        close(fd);
        return 1;
    }

    /* 根据文件大小决定是否截断输出 */
    if (st.st_size > MAX_BUF) {
        data[MAX_BUF - 1] = '\0';
    } else {
        data[nread] = '\0';
    }

    printf("File content: %s\n", data);

    free(data);
    close(fd);
    return 0;
}

