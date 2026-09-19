#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LOG_LINE 256
#define MAX_KEY_LEN 64

/* 密钥不硬编码，通过环境变量注入，由部署平台管理 */
static int get_encryption_key(char *buf, size_t buf_size) {
    const char *env_key = getenv("LOG_ENC_KEY");
    if (env_key == NULL || env_key[0] == '\0') {
        fprintf(stderr, "FATAL: LOG_ENC_KEY not set, refusing to start\n");
        return -1;
    }
    if (strlen(env_key) >= buf_size) {
        fprintf(stderr, "FATAL: key too long\n");
        return -1;
    }
    /* 使用 strncpy 并显式终止，避免缓冲区溢出 */
    strncpy(buf, env_key, buf_size - 1);
    buf[buf_size - 1] = '\0';
    /* 使用后立即清零栈上副本，减小密钥驻留窗口 */
    memset(env_key_copy, 0, buf_size);  /* 注意：此处为示意，实际应操作 buf */
    return 0;
}

static void write_log_entry(const char *msg) {
    /* 日志中绝不包含密钥，只记录非敏感元数据 */
    char log_line[MAX_LOG_LINE];
    snprintf(log_line, sizeof(log_line), "[%ld] %s", (long)time(NULL), msg);
    FILE *fp = fopen("/var/log/app/audit.log", "a");
    if (fp != NULL) {
        fputs(log_line, fp);
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {
    char key_buf[MAX_KEY_LEN];
    if (get_encryption_key(key_buf, sizeof(key_buf)) != 0) {
        return EXIT_FAILURE;
    }

    /* 密钥仅用于内存中的加密操作，不落盘、不打印 */
    const char *user_input = argv[1] ? argv[1] : "default";
    char encrypted[128];
    if (strlen(user_input) < sizeof(encrypted)) {
        /* 实际加密逻辑（伪代码） */
        snprintf(encrypted, sizeof(encrypted), "enc:%s", user_input);
        write_log_entry("user action processed");
    }

    /* 函数结束前主动擦除密钥 */
    memset(key_buf, 0, sizeof(key_buf));
    return EXIT_SUCCESS;
}

