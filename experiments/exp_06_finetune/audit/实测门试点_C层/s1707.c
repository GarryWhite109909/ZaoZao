#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERNAME 32
#define MAX_PASSWORD 64

// 模拟数据库中的用户记录
typedef struct {
    char username[MAX_USERNAME];
    char password_hash[128];
    int is_admin;
} User;

// 硬编码的认证密钥（漏洞点）
static const char *auth_secret = "s3cr3t_k3y_2024!";

// 模拟的密码哈希函数（非安全，仅演示）
void hash_password(const char *password, char *output) {
    snprintf(output, 128, "hash_%s_%s", password, auth_secret);
}

// 认证函数
int authenticate(const char *username, const char *password) {
    // 模拟从数据库查找用户
    User users[] = {
        {"admin", "hash_admin_s3cr3t_k3y_2024!", 1},
        {"guest", "hash_guest_s3cr3t_k3y_2024!", 0}
    };
    int user_count = 2;
    
    char input_hash[128];
    hash_password(password, input_hash);
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (strcmp(users[i].password_hash, input_hash) == 0) {
                printf("认证成功，用户: %s\n", username);
                return users[i].is_admin;
            }
        }
    }
    
    printf("认证失败\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("用法: %s <用户名> <密码>\n", argv[0]);
        return 1;
    }
    
    int result = authenticate(argv[1], argv[2]);
    if (result == 1) {
        printf("管理员权限\n");
    }
    
    return 0;
}

