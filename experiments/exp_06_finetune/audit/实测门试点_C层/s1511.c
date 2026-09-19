#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define CONFIG_DIR "/etc/myapp/conf/"

/* 加载配置文件到全局缓冲区 */
static char g_config_buf[4096];

int load_config(const char *user_input) {
    char filepath[MAX_PATH];
    FILE *fp;
    size_t bytes_read;

    /* 拼接配置文件路径 */
    snprintf(filepath, sizeof(filepath), "%s%s", CONFIG_DIR, user_input);

    /* 打开并读取配置文件 */
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "无法打开配置文件: %s\n", filepath);
        return -1;
    }

    bytes_read = fread(g_config_buf, 1, sizeof(g_config_buf) - 1, fp);
    fclose(fp);

    if (bytes_read == 0) {
        fprintf(stderr, "配置文件为空\n");
        return -1;
    }

    g_config_buf[bytes_read] = '\0';
    printf("配置加载成功: %s\n", filepath);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <配置文件名>\n", argv[0]);
        return 1;
    }
    return load_config(argv[1]);
}

