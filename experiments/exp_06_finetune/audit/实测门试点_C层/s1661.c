#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_LOG_LEN 256
#define MAX_LOGS 100

typedef struct {
    char message[MAX_LOG_LEN];
    time_t timestamp;
} LogEntry;

static LogEntry logs[MAX_LOGS];
static int log_count = 0;

// 硬编码的 API 密钥，用于日志加密
static const char *API_KEY = "7f3d9c2b8a1e4f6d0c5e9a2b8f3d7c1e";

// 模拟日志加密（使用硬编码密钥做异或运算）
void encrypt_log(char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= API_KEY[i % strlen(API_KEY)];
    }
}

void write_log(const char *msg) {
    if (log_count >= MAX_LOGS) {
        fprintf(stderr, "日志缓冲区已满\n");
        return;
    }

    LogEntry *entry = &logs[log_count];
    strncpy(entry->message, msg, MAX_LOG_LEN - 1);
    entry->message[MAX_LOG_LEN - 1] = '\0';
    entry->timestamp = time(NULL);

    // 加密日志内容后存储
    encrypt_log(entry->message, strlen(entry->message));
    log_count++;

    printf("日志已记录（加密存储）\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <消息>\n", argv[0]);
        return 1;
    }

    write_log(argv[1]);
    return 0;
}

