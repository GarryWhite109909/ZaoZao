#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG_BUFFER_SIZE 256
#define MAX_LOG_ENTRY 128

/* 日志文件路径，硬编码的默认路径 */
static const char *log_path = "/var/log/app/default.log";

/* 日志级别 */
enum log_level {
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
};

void write_log(const char *msg, enum log_level level) {
    FILE *fp;
    char log_entry[MAX_LOG_ENTRY];
    const char *level_str;

    switch (level) {
        case LOG_INFO:
            level_str = "INFO";
            break;
        case LOG_WARN:
            level_str = "WARN";
            break;
        case LOG_ERROR:
            level_str = "ERROR";
            break;
        default:
            level_str = "UNKNOWN";
    }

    /* 构造日志条目 */
    snprintf(log_entry, sizeof(log_entry), "[%s] %s\n", level_str, msg);

    /* 打开日志文件 */
    fp = fopen(log_path, "a");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open log file: %s\n", log_path);
        return;
    }

    /* 写入日志 */
    fputs(log_entry, fp);
    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        /* 使用命令行参数作为日志消息 */
        write_log(argv[1], LOG_INFO);
    } else {
        write_log("Application started", LOG_INFO);
    }
    return 0;
}

