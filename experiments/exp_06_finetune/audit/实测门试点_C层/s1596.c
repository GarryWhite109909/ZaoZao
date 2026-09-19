#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define CONFIG_DIR "/etc/myapp/configs/"

// line 8: 加载用户指定的配置文件
int load_config(const char *user_input) {
    char filepath[MAX_PATH];
    FILE *fp;
    char buffer[128];

    // line 12: 直接拼接用户输入到路径中，未做任何校验
    snprintf(filepath, sizeof(filepath), "%s%s", CONFIG_DIR, user_input);

    fp = fopen(filepath, "r");
    if (fp == NULL) {
        printf("Config file not found: %s\n", filepath);
        return -1;
    }

    // 读取配置内容并处理
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // 模拟配置处理逻辑
        if (strncmp(buffer, "timeout=", 8) == 0) {
            int timeout = atoi(buffer + 8);
            printf("Set timeout to %d seconds\n", timeout);
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <config_name>\n", argv[0]);
        return 1;
    }

    // line 35: 用户输入直接传入配置加载函数
    load_config(argv[1]);
    return 0;
}

