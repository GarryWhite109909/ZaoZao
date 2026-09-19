#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_PATH "/tmp/device_config"
#define MAX_CONFIG_SIZE 128

/* 固件配置更新模块：检查文件属性后读取内容 */
int load_firmware_config(char *output, size_t out_size) {
    struct stat st;
    int fd;
    char *buf = NULL;
    ssize_t nread;

    /* 第14行：先检查文件是否为普通文件且非符号链接 */
    if (lstat(CONFIG_PATH, &st) != 0) {
        perror("lstat failed");
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Config is not a regular file\n");
        return -1;
    }

    /* 第22行：检查通过后打开文件（存在TOCTOU窗口） */
    fd = open(CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    buf = (char *)malloc(MAX_CONFIG_SIZE);
    if (!buf) {
        close(fd);
        return -1;
    }

    /* 第32行：读取内容到缓冲区 */
    nread = read(fd, buf, MAX_CONFIG_SIZE - 1);
    if (nread < 0) {
        perror("read failed");
        free(buf);
        close(fd);
        return -1;
    }
    buf[nread] = '\0';

    /* 复制到输出 */
    if (nread >= (ssize_t)out_size) {
        free(buf);
        close(fd);
        return -1;
    }
    memcpy(output, buf, (size_t)nread + 1);

    free(buf);
    close(fd);
    return 0;
}

int main(void) {
    char config[MAX_CONFIG_SIZE] = {0};
    if (load_firmware_config(config, sizeof(config)) == 0) {
        printf("Config loaded: %s\n", config);
    }
    return 0;
}

