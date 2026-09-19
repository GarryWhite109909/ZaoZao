#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH_LEN 256
#define CONFIG_DIR "/etc/myapp/configs/"

/* 加载配置文件并返回文件内容 */
char* load_config(const char* filename) {
    char full_path[MAX_PATH_LEN];
    FILE* fp;
    char* content;
    long file_size;

    /* 拼接完整路径 */
    snprintf(full_path, sizeof(full_path), "%s%s", CONFIG_DIR, filename);
    
    /* 打开配置文件 */
    fp = fopen(full_path, "r");
    if (fp == NULL) {
        return NULL;
    }

    /* 获取文件大小 */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* 分配内存并读取内容 */
    content = (char*)malloc(file_size + 1);
    if (content == NULL) {
        fclose(fp);
        return NULL;
    }

    size_t read_size = fread(content, 1, file_size, fp);
    content[read_size] = '\0';
    fclose(fp);

    return content;
}

/* 根据用户输入加载配置 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <config_name>\n", argv[0]);
        return 1;
    }

    char* config_content = load_config(argv[1]);
    if (config_content == NULL) {
        printf("Failed to load config: %s\n", argv[1]);
        return 1;
    }

    printf("Config loaded: %s\n", config_content);
    free(config_content);
    return 0;
}

