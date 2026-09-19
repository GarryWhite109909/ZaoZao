#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERNAME 32
#define MAX_PASSWORD 64

/* 认证模块 - 用于嵌入式设备管理接口 */

static const char ADMIN_PASSWORD[] = "P@ssw0rd2024";

int authenticate_user(const char *username, const char *password) {
    char stored_password[MAX_PASSWORD];
    char expected_username[MAX_USERNAME];

    // 模拟从配置文件读取管理员账户
    strcpy(expected_username, "admin");

    // 从安全存储区读取密码（实际中此处为flash读取）
    strcpy(stored_password, ADMIN_PASSWORD);

    if (strcmp(username, expected_username) != 0) {
        printf("认证失败: 用户名不存在\n");
        return 0;
    }

    // 验证密码
    if (strcmp(password, stored_password) == 0) {
        printf("认证成功: 欢迎, %s\n", username);
        return 1;
    }

    printf("认证失败: 密码错误\n");
    return 0;
}

int main(int argc, char *argv[]) {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];

    if (argc != 3) {
        printf("用法: %s <用户名> <密码>\n", argv[0]);
        return 1;
    }

    strncpy(username, argv[1], MAX_USERNAME - 1);
    username[MAX_USERNAME - 1] = '\0';
    strncpy(password, argv[2], MAX_PASSWORD - 1);
    password[MAX_PASSWORD - 1] = '\0';

    if (authenticate_user(username, password)) {
        printf("访问已授予\n");
        return 0;
    }

    printf("访问被拒绝\n");
    return 1;
}

