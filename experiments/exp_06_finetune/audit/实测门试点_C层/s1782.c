#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH 256
#define CONFIG_DIR "/etc/myapp/configs"

/* 从配置文件加载设置 */
int load_config(const char *user_input) {
    char filepath[MAX_PATH];
    FILE *fp;
    char buffer[128];

    // 构造配置文件路径
    snprintf(filepath, sizeof(filepath), "%s/%s", CONFIG_DIR, user_input);
    
    printf("Loading config from: %s\n", filepath);
    
    // 打开配置文件
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        perror("Failed to open config file");
        return -1;
    }
    
    // 读取配置内容
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("Config: %s", buffer);
    }
    
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_name>\n", argv[0]);
        return 1;
    }
    
    // 调用配置加载函数
    return load_config(argv[1]);
}

