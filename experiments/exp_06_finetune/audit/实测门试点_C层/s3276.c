#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CMD_LEN 64
#define MAX_LOG_SIZE 128

typedef struct {
    char log_buf[MAX_LOG_SIZE];
    size_t log_len;
    int valid;
} LogBuffer;

static int append_to_log(LogBuffer *lb, const char *data, size_t len) {
    if (!lb || !data || len == 0) return -1;
    if (lb->log_len + len > sizeof(lb->log_buf)) {
        return -2;
    }
    memcpy(lb->log_buf + lb->log_len, data, len);
    lb->log_len += len;
    return 0;
}

static void process_command(const char *cmd, size_t cmd_len) {
    if (!cmd || cmd_len >= MAX_CMD_LEN) return;
    
    char local_buf[MAX_CMD_LEN];
    memcpy(local_buf, cmd, cmd_len);
    local_buf[cmd_len] = '\0';
    
    LogBuffer *lb = (LogBuffer*)calloc(1, sizeof(LogBuffer));
    if (!lb) return;
    
    if (append_to_log(lb, local_buf, strnlen(local_buf, MAX_CMD_LEN)) == 0) {
        printf("Log entry: %s\n", lb->log_buf);
    }
    
    free(lb);
    lb = NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        return 1;
    }
    
    char cmd[MAX_CMD_LEN];
    strncpy(cmd, argv[1], MAX_CMD_LEN - 1);
    cmd[MAX_CMD_LEN - 1] = '\0';
    
    process_command(cmd, strnlen(cmd, MAX_CMD_LEN));
    return 0;
}

