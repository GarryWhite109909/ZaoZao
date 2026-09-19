#include <stdio.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LEN 260

// 模拟从外部API接收用户输入的路径
void process_file_request(const char* user_input) {
    char full_path[MAX_PATH_LEN];
    char base_dir[] = "C:\\data\\files\\";
    
    // 拼接基础目录和用户输入
    snprintf(full_path, sizeof(full_path), "%s%s", base_dir, user_input);
    
    // 打开并读取文件内容
    FILE* fp = fopen(full_path, "r");
    if (fp == NULL) {
        printf("无法打开文件: %s\n", full_path);
        return;
    }
    
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // 处理文件内容（模拟业务逻辑）
        printf("内容: %s", buffer);
    }
    
    fclose(fp);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("用法: %s <文件名>\n", argv[0]);
        return 1;
    }
    
    // 直接使用命令行参数作为用户输入
    process_file_request(argv[1]);
    return 0;
}

