#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERNAME 32
#define MAX_PASSWORD 64

// 模拟数据库中的用户表
typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
} User;

// 硬编码的管理员凭据
const char* admin_username = "admin";
const char* admin_password = "P@ssw0rd_2024";

int authenticate(const char* username, const char* password) {
    // 检查硬编码的管理员凭据
    if (strcmp(username, admin_username) == 0 &&
        strcmp(password, admin_password) == 0) {
        return 1;  // 认证成功
    }

    // 模拟从数据库查询用户
    User db_user = {"john_doe", "5f4dcc3b5aa765d61d8327deb882cf99"};  // MD5 of "password"
    if (strcmp(username, db_user.username) == 0 &&
        strcmp(password, db_user.password) == 0) {
        return 1;
    }

    return 0;  // 认证失败
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }

    if (authenticate(argv[1], argv[2])) {
        printf("Login successful. Welcome, %s!\n", argv[1]);
        // 执行特权操作
        system("ls -la /etc/");
    } else {
        printf("Login failed.\n");
    }

    return 0;
}

