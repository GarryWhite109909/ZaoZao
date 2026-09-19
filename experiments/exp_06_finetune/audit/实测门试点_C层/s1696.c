#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#define MAX_LOG_LEN 256

// 日志缓冲区
static char log_buffer[MAX_LOG_LEN];

// 模拟从配置文件读取日志服务器地址
static const char* get_log_server() {
    // 实际项目中可能从配置文件读取
    return "10.0.0.5";
}

// 模拟获取当前用户
static const char* get_current_user() {
    return "admin";
}

// 记录用户登录事件
void log_user_login(const char* username) {
    char log_entry[MAX_LOG_LEN];
    const char* server = get_log_server();
    
    // 构造日志内容
    snprintf(log_entry, sizeof(log_entry), 
             "User %s logged in at %s", 
             username, __TIME__);
    
    // 将日志写入系统日志
    openlog("auth", LOG_PID, LOG_AUTH);
    syslog(LOG_INFO, "%s", log_entry);
    closelog();
    
    // 将日志发送到远程服务器
    char command[MAX_LOG_LEN];
    snprintf(command, sizeof(command), 
             "logger -h %s -p auth.info '%s'", 
             server, log_entry);
    
    // 执行命令发送日志
    system(command);
    
    // 记录到本地文件
    FILE* fp = fopen("/var/log/auth.log", "a");
    if (fp) {
        fprintf(fp, "%s\n", log_entry);
        fclose(fp);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }
    
    log_user_login(argv[1]);
    return 0;
}

