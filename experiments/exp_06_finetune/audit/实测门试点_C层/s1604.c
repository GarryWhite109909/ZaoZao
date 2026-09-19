#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define MAX_SERIAL_DATA 1024

// 从序列化数据中提取文件名，并加载对应配置
int load_serialized_config(const char *serialized_data) {
    char filename[MAX_PATH];
    char filepath[MAX_PATH];
    FILE *fp;
    char buffer[256];

    // 模拟从序列化数据中解析出文件名
    const char *name_start = strstr(serialized_data, "filename=");
    if (name_start == NULL) {
        fprintf(stderr, "Invalid serialized data: no filename field\n");
        return -1;
    }
    name_start += strlen("filename=");
    
    // 提取文件名直到分隔符或结束
    const char *name_end = strchr(name_start, ';');
    if (name_end == NULL) {
        name_end = serialized_data + strlen(serialized_data);
    }
    size_t name_len = name_end - name_start;
    if (name_len >= MAX_PATH) {
        fprintf(stderr, "Filename too long\n");
        return -1;
    }
    memcpy(filename, name_start, name_len);
    filename[name_len] = '\0';

    // 构造完整路径（有漏洞：直接拼接，未做路径规范化检查）
    snprintf(filepath, sizeof(filepath), "/etc/app/configs/%s", filename);

    // 打开并读取配置文件
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open config file: %s\n", filepath);
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // 处理配置项（简化处理）
        printf("Config: %s", buffer);
    }
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <serialized_data>\n", argv[0]);
        return 1;
    }
    return load_serialized_config(argv[1]);
}

