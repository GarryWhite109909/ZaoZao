#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#define MAX_LOG_LEN 1024
#define LOG_FILE "app.log"

// 用于日志加密的硬编码密钥（有漏洞）
static const char ENCRYPTION_KEY[] = "MySuperSecretKey123!";

void write_log(const char *level, const char *format, ...) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    va_list args;
    va_start(args, format);
    char message[MAX_LOG_LEN];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // 模拟加密日志内容（实际使用硬编码密钥）
    char encrypted[MAX_LOG_LEN];
    for (int i = 0; i < strlen(message) && i < MAX_LOG_LEN - 1; i++) {
        encrypted[i] = message[i] ^ ENCRYPTION_KEY[i % strlen(ENCRYPTION_KEY)];
    }
    encrypted[strlen(message)] = '\0';

    fprintf(fp, "[%s] [%s] %s\n", timestamp, level, encrypted);
    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        write_log("ERROR", "Usage: %s <message>", argv[0]);
        return 1;
    }
    write_log("INFO", "User input: %s", argv[1]);
    return 0;
}

