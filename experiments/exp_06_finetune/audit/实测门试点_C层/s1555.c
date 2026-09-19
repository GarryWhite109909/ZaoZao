#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH_LEN 256
#define CONFIG_DIR "/etc/myapp/configs/"

typedef struct {
    char name[64];
    int enabled;
} AppConfig;

int load_config(const char *user_input, AppConfig *cfg) {
    char filepath[MAX_PATH_LEN];
    FILE *fp;
    char line[128];

    // 构造配置文件路径
    snprintf(filepath, sizeof(filepath), "%s%s.conf", CONFIG_DIR, user_input);
    
    // 打开配置文件
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        printf("配置文件不存在: %s\n", filepath);
        return -1;
    }

    // 读取配置项
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "name=", 5) == 0) {
            strncpy(cfg->name, line + 5, strcspn(line + 5, "\n"));
            if (strlen(cfg->name) >= sizeof(cfg->name)) {
                cfg->name[sizeof(cfg->name) - 1] = '\0';
            }
        } else if (strncmp(line, "enabled=", 8) == 0) {
            cfg->enabled = atoi(line + 8);
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法: %s <配置名>\n", argv[0]);
        return 1;
    }

    AppConfig cfg = {0};
    if (load_config(argv[1], &cfg) == 0) {
        printf("配置加载成功: %s (enabled=%d)\n", cfg.name, cfg.enabled);
    }
    return 0;
}

