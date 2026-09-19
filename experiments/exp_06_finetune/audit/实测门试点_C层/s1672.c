#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define CONFIG_DIR "/etc/myapp/configs/"

/* 根据配置名加载配置文件的简化实现 */
char *load_config(const char *config_name) {
    char filepath[MAX_PATH];
    char *buffer = NULL;
    long file_size;
    FILE *fp;

    /* 拼接配置路径 */
    snprintf(filepath, sizeof(filepath), "%s%s", CONFIG_DIR, config_name);

    fp = fopen(filepath, "rb");
    if (fp == NULL) {
        return NULL;
    }

    /* 获取文件大小 */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(fp);
        return NULL;
    }

    /* 分配缓冲区并读取文件 */
    buffer = (char *)malloc(file_size + 1);
    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, file_size, fp);
    buffer[read_size] = '\0';
    fclose(fp);

    return buffer;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <config_name>\n", argv[0]);
        return 1;
    }

    char *content = load_config(argv[1]);
    if (content == NULL) {
        printf("Failed to load config\n");
        return 1;
    }

    printf("Config content: %s\n", content);
    free(content);
    return 0;
}

