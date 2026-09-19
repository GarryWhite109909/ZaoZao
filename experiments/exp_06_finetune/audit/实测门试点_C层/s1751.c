#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FILE_SIZE 1024

// 文件上传处理函数
int handle_upload(const char *filename, const char *content) {
    char filepath[256];
    char buffer[MAX_FILE_SIZE];
    
    // 1. 拼接文件路径
    sprintf(filepath, "/uploads/%s", filename);
    
    // 2. 检查文件大小
    if (strlen(content) > MAX_FILE_SIZE) {
        printf("File too large\n");
        return -1;
    }
    
    // 3. 写入文件
    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        printf("Failed to open file\n");
        return -1;
    }
    
    // 4. 复制内容到缓冲区
    strcpy(buffer, content);
    
    // 5. 写入缓冲区内容
    fwrite(buffer, 1, strlen(buffer), fp);
    fclose(fp);
    
    printf("File uploaded successfully: %s\n", filepath);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <filename> <content>\n", argv[0]);
        return 1;
    }
    
    // 调用上传处理函数
    return handle_upload(argv[1], argv[2]);
}

