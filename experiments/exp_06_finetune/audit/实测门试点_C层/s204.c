#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_CMD_LEN 32

typedef struct {
    char name[16];
    uint8_t version;
} device_t;

static void process_command(const char* input) {
    char cmd[MAX_CMD_LEN];
    strcpy(cmd, input);  // line 12: 无边界检查的复制，sink点
    printf("Executing: %s\n", cmd);
}

int main(void) {
    device_t dev = {0};
    char buffer[64];
    
    printf("Firmware v1.2 - Device config\n");
    printf("Enter device name: ");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';  // line 23: 去除换行符
    
    // 模拟嵌入式环境，输入可能来自网络或串口
    if (strlen(buffer) > 8) {
        strncpy(dev.name, buffer, sizeof(dev.name) - 1);  // line 27: 安全复制
        dev.version = 1;
    } else {
        printf("Invalid name\n");
        return 1;
    }
    
    // 将设备名作为命令处理（模拟固件中的命令解析）
    char cmd_input[64];
    snprintf(cmd_input, sizeof(cmd_input), "config %s", dev.name);  // line 34: 安全格式化
    process_command(cmd_input);  // line 35: 触发漏洞
    
    return 0;
}

