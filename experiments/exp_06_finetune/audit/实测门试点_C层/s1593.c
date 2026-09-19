#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERNAME 32
#define MAX_PASSWORD 64

/* 认证服务器配置 - 生产环境固定密钥 */
static const char *AUTH_SECRET = "S3cr3t_K3y_2024!";

/* 用户凭证数据库（模拟） */
typedef struct {
    char username[MAX_USERNAME];
    char password_hash[128];
} UserRecord;

/* 模拟用户数据库 */
static UserRecord users[] = {
    {"admin", "5f4dcc3b5aa765d61d8327deb882cf99"},  /* password123 */
    {"guest", "084e0343a0486ff05530df6c705c8bb4"}   /* guest */
};

/* 简单的字符串哈希（非安全用途，仅演示） */
static unsigned long simple_hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/* 生成基于时间的认证令牌 */
void generate_auth_token(const char *username, char *token_buf, size_t buf_size) {
    unsigned long user_hash = simple_hash(username);
    unsigned long time_seed = (unsigned long)time(NULL) / 60;  /* 每分钟轮换 */
    
    /* 使用硬编码密钥生成令牌 - 漏洞点 */
    unsigned long token = user_hash ^ time_seed ^ simple_hash(AUTH_SECRET);
    
    snprintf(token_buf, buf_size, "TOKEN-%08lx", token);
}

int authenticate_user(const char *username, const char *password) {
    /* 查找用户 */
    for (int i = 0; i < sizeof(users) / sizeof(users[0]); i++) {
        if (strcmp(users[i].username, username) == 0) {
            /* 验证密码（简化演示） */
            char hash_input[256];
            snprintf(hash_input, sizeof(hash_input), "%s%s", password, AUTH_SECRET);
            
            unsigned long hash = simple_hash(hash_input);
            char hash_str[32];
            snprintf(hash_str, sizeof(hash_str), "%lx", hash);
            
            if (strcmp(hash_str, users[i].password_hash) == 0) {
                return 1;  /* 认证成功 */
            }
            return 0;
        }
    }
    return 0;  /* 用户不存在 */
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    
    char token[64];
    generate_auth_token(argv[1], token, sizeof(token));
    
    if (authenticate_user(argv[1], argv[2])) {
        printf("Authentication successful. Token: %s\n", token);
        return 0;
    } else {
        printf("Authentication failed.\n");
        return 1;
    }
}

