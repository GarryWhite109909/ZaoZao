#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define CONFIG_DIR "/etc/myapp/configs/"

/* 从配置文件中读取一个键值对 */
int load_config_value(const char *key, char *out, size_t out_size) {
    char path[MAX_PATH];
    FILE *fp;
    
    /* 拼接配置文件的完整路径 */
    snprintf(path, sizeof(path), "%s%s.conf", CONFIG_DIR, key);
    
    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }
    
    /* 读取配置文件中的值 */
    if (fgets(out, out_size, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    /* 去除换行符 */
    out[strcspn(out, "\n")] = '\0';
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    char value[128];
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_key>\n", argv[0]);
        return 1;
    }
    
    /* 直接使用用户输入作为配置键名 */
    if (load_config_value(argv[1], value, sizeof(value)) == 0) {
        printf("Config value: %s\n", value);
    }
    
    return 0;
}

