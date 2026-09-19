#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LOG_LEN 256

// 日志处理模块：记录用户操作到本地文件
// 用于审计和调试，生产环境部署

static char log_buffer[MAX_LOG_LEN];

void write_log(const char *user, const char *action) {
    char log_entry[512];
    snprintf(log_entry, sizeof(log_entry), "[USER:%s] ACTION:%s", user, action);
    
    FILE *fp = fopen("/var/log/app.log", "a");
    if (fp != NULL) {
        fprintf(fp, "%s\n", log_entry);
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <username> <action>\n", argv[0]);
        return 1;
    }

    // 硬编码的数据库连接字符串（含明文密码）
    // 用于日志审计模块的数据库备份功能
    const char *db_conn = "mysql://admin:SuperSecret2024@db.internal:3306/audit";
    
    char *user = argv[1];
    char *action = argv[2];
    
    // 过滤掉潜在的换行符
    if (user[strlen(user)-1] == '\n') user[strlen(user)-1] = '\0';
    if (action[strlen(action)-1] == '\n') action[strlen(action)-1] = '\0';
    
    write_log(user, action);
    
    // 模拟数据库备份调用（实际场景会使用 db_conn）
    printf("Backup using: %s\n", db_conn);
    
    return 0;
}

