#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256

// 模拟从HTTP请求中提取文件名的函数
char* get_request_param(const char* param_name) {
    // 简化：返回一个硬编码的路径，实际场景中来自用户输入
    return strdup("../../etc/passwd");
}

// 根据文件名读取文件内容
void read_file(const char* filename) {
    char filepath[MAX_PATH];
    char buffer[128];
    FILE* fp;
    
    // 漏洞点：直接拼接用户输入到路径
    snprintf(filepath, sizeof(filepath), "/var/www/uploads/%s", filename);
    
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        printf("File not found\n");
        return;
    }
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    fclose(fp);
}

// API入口函数
void api_download_file() {
    char* filename = get_request_param("filename");
    
    if (filename == NULL) {
        printf("Invalid parameter\n");
        return;
    }
    
    read_file(filename);
    free(filename);
}

int main() {
    api_download_file();
    return 0;
}

