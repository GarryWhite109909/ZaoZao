#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define CONFIG_PATH "/tmp/device_config"
#define MAX_BUF 256

/* 固件启动时加载设备配置，含敏感参数（如加密密钥、调试开关） */
static int load_config(const char *path, char *out, size_t out_sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open config failed: %s\n", strerror(errno));
        return -1;
    }
    ssize_t n = read(fd, out, out_sz - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "read config failed\n");
        return -1;
    }
    out[n] = '\0';
    return 0;
}

/* 校验文件属主是否为 root，防止非特权用户篡改配置 */
static int verify_owner(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (st.st_uid != 0) {
        fprintf(stderr, "config owner not root\n");
        return -1;
    }
    return 0;
}

int main(void) {
    char config[MAX_BUF] = {0};

    /* 先校验属主，再打开读取 —— 存在 TOCTOU 窗口 */
    if (verify_owner(CONFIG_PATH) != 0) {
        return 1;
    }
    if (load_config(CONFIG_PATH, config, sizeof(config)) != 0) {
        return 1;
    }

    /* 模拟使用配置中的调试开关（如 1=启用调试串口） */
    if (strstr(config, "debug=1") != NULL) {
        printf("Debug mode enabled (sensitive)\n");
    }
    printf("Config loaded: %s\n", config);
    return 0;
}

