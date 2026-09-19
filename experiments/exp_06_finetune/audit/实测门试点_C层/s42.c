#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define CONFIG_PATH "/tmp/fw_config.bin"
#define BUF_SIZE 256

/* 固件配置更新流程：先检查文件权限，再打开并读取内容 */
int update_firmware_config(const char *new_data, size_t len) {
    struct stat st;
    int fd = -1;
    char *buffer = NULL;
    ssize_t bytes_read;
    int ret = -1;

    /* 第13行：前置检查 - 验证文件所有权和权限 */
    if (stat(CONFIG_PATH, &st) != 0) {
        perror("stat");
        return -1;
    }
    if (st.st_uid != getuid() || (st.st_mode & S_IWOTH)) {
        fprintf(stderr, "权限检查失败\n");
        return -1;
    }

    /* 第21行：TOCTOU窗口 - 检查与实际打开之间可被替换 */
    fd = open(CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    buffer = (char *)malloc(BUF_SIZE);
    if (!buffer) {
        close(fd);
        return -1;
    }

    /* 第31行：读取文件内容（此时可能已指向攻击者控制的文件） */
    bytes_read = read(fd, buffer, BUF_SIZE - 1);
    if (bytes_read < 0) {
        perror("read");
        goto cleanup;
    }
    buffer[bytes_read] = '\0';

    /* 模拟配置应用：检查魔数 */
    if (bytes_read < 4 || memcmp(buffer, "FWCF", 4) != 0) {
        fprintf(stderr, "无效配置格式\n");
        goto cleanup;
    }

    /* 第43行：使用读取的数据 */
    printf("配置校验通过，长度: %zd\n", bytes_read);
    ret = 0;

cleanup:
    if (buffer) {
        free(buffer);
        buffer = NULL;  /* 第50行：释放后置NULL */
    }
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <数据>\n", argv[0]);
        return 1;
    }
    return update_firmware_config(argv[1], strlen(argv[1]));
}

