#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define CONFIG_PATH "/tmp/fw_config"
#define MAX_BUF 128

/* 固件配置更新函数 */
static int update_firmware_config(const char *new_config) {
    FILE *fp = NULL;
    char buf[MAX_BUF];
    struct stat st;
    int fd = -1;

    /* 检查配置文件是否存在（TOCTOU窗口） */
    if (access(CONFIG_PATH, F_OK) != 0) {
        fprintf(stderr, "Config file not found, creating...\n");
    }

    /* 打开配置文件（攻击者可在此替换为符号链接） */
    fd = open(CONFIG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    /* 写入新配置 */
    if (write(fd, new_config, strlen(new_config)) < 0) {
        perror("write");
        close(fd);
        return -1;
    }

    close(fd);
    printf("Config updated: %s\n", new_config);
    return 0;
}

/* 固件启动时加载配置 */
static int load_firmware_config(void) {
    FILE *fp = fopen(CONFIG_PATH, "r");
    char buf[MAX_BUF];
    if (!fp) {
        perror("fopen");
        return -1;
    }
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        printf("Loaded config: %s", buf);
    }
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_data>\n", argv[0]);
        return 1;
    }

    /* 模拟固件升级流程 */
    if (update_firmware_config(argv[1]) != 0) {
        return 1;
    }
    load_firmware_config();
    return 0;
}

