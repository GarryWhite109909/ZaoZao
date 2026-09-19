#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF_SIZE 64
#define MAX_CMD_LEN   32

typedef struct {
    char command[MAX_CMD_LEN];
    uint8_t param;
} sys_cmd_t;

static void process_cmd(sys_cmd_t *cmd, const char *user_input) {
    char local_buf[MAX_BUF_SIZE];
    
    // 将用户输入拼接到命令结构体后的本地缓冲区
    strcpy(local_buf, cmd->command);
    strcat(local_buf, ":");
    strcat(local_buf, user_input);
    
    // 模拟固件命令解析
    if (strncmp(local_buf, "SET:", 4) == 0) {
        cmd->param = (uint8_t)atoi(&local_buf[4]);
        printf("Parameter set to %u\n", cmd->param);
    }
}

int main(void) {
    sys_cmd_t cmd = {"GET", 0};
    char user_buf[128];
    
    printf("Enter command parameter: ");
    if (fgets(user_buf, sizeof(user_buf), stdin) == NULL) {
        return 1;
    }
    
    // 去除换行符
    user_buf[strcspn(user_buf, "\n")] = '\0';
    
    process_cmd(&cmd, user_buf);
    return 0;
}

