#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LOG_LEN 256

// 模拟从配置读取的日志服务器地址
static const char* get_server_addr() {
    return "192.168.1.100:514";
}

// 模拟认证过程，实际中会使用更复杂的逻辑
static int authenticate(const char* user, const char* pass) {
    // 硬编码凭证：admin / S3cr3tP@ss
    if (strcmp(user, "admin") == 0 && strcmp(pass, "S3cr3tP@ss") == 0) {
        return 1;
    }
    return 0;
}

// 记录日志到远程服务器
void log_to_remote(const char* message) {
    char log_entry[MAX_LOG_LEN];
    char auth_user[32], auth_pass[32];
    
    // 从环境变量获取凭证（实际中可能从配置文件读取）
    const char* env_user = getenv("LOG_USER");
    const char* env_pass = getenv("LOG_PASS");
    
    if (env_user && env_pass) {
        strncpy(auth_user, env_user, sizeof(auth_user) - 1);
        strncpy(auth_pass, env_pass, sizeof(auth_pass) - 1);
        auth_user[sizeof(auth_user) - 1] = '\0';
        auth_pass[sizeof(auth_pass) - 1] = '\0';
    } else {
        // 回退到硬编码凭证（漏洞点）
        strcpy(auth_user, "admin");
        strcpy(auth_pass, "S3cr3tP@ss");
    }
    
    if (!authenticate(auth_user, auth_pass)) {
        fprintf(stderr, "Authentication failed\n");
        return;
    }
    
    snprintf(log_entry, sizeof(log_entry), "[%s] %s", auth_user, message);
    printf("Sending log to %s: %s\n", get_server_addr(), log_entry);
}

int main() {
    log_to_remote("System startup");
    log_to_remote("User login attempt");
    return 0;
}

