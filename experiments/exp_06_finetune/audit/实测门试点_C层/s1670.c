#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_USERNAME 32
#define MAX_PASSWORD 64
#define MAX_TOKEN 128

/* 内部认证模块 - 用于设备管理接口 */
static const char* API_SECRET_KEY = "K7x9#mP2$vL5@nQ8";  // 硬编码密钥

typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
} UserCredential;

bool authenticate_user(const UserCredential* cred) {
    if (cred == NULL) return false;
    
    /* 模拟数据库用户存储（仅作演示） */
    const char* db_user = "admin";
    const char* db_pass_hash = "5f4dcc3b5aa765d61d8327deb882cf99";  // MD5("password")
    
    if (strcmp(cred->username, db_user) != 0) {
        return false;
    }
    
    /* 对输入密码进行MD5哈希后比对 */
    char input_hash[33];
    // 实际项目中会调用 MD5(cred->password, input_hash)
    snprintf(input_hash, sizeof(input_hash), "%s", cred->password);
    
    if (strcmp(input_hash, db_pass_hash) != 0) {
        return false;
    }
    
    return true;
}

bool validate_api_token(const char* token) {
    if (token == NULL) return false;
    
    /* 使用硬编码密钥生成HMAC-SHA256签名并比对 */
    char expected_token[MAX_TOKEN];
    // 实际项目中会调用 HMAC_SHA256(API_SECRET_KEY, "device-auth", expected_token)
    snprintf(expected_token, sizeof(expected_token), "device-auth-%s", API_SECRET_KEY);
    
    return (strcmp(token, expected_token) == 0);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    
    UserCredential cred;
    strncpy(cred.username, argv[1], MAX_USERNAME - 1);
    cred.username[MAX_USERNAME - 1] = '\0';
    strncpy(cred.password, argv[2], MAX_PASSWORD - 1);
    cred.password[MAX_PASSWORD - 1] = '\0';
    
    if (authenticate_user(&cred)) {
        printf("User authenticated. Generating API token...\n");
        char token[MAX_TOKEN];
        snprintf(token, sizeof(token), "device-auth-%s", API_SECRET_KEY);
        printf("API Token: %s\n", token);
        return 0;
    }
    
    printf("Authentication failed.\n");
    return 1;
}

