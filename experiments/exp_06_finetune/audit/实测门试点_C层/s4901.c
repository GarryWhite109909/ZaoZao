#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CMD_LEN 64
#define MAX_RESP_LEN 128

typedef struct {
    char command[MAX_CMD_LEN];
    char response[MAX_RESP_LEN];
    int valid;
} CommandBuffer;

int process_command(CommandBuffer *buf, const char *input, size_t input_len) {
    // line 12: 边界检查 - 拒绝超长输入
    if (input_len >= MAX_CMD_LEN) {
        buf->valid = 0;
        return -1;
    }
    
    // line 17: 使用 memcpy 替代 strcpy，显式控制拷贝长度
    memcpy(buf->command, input, input_len);
    buf->command[input_len] = '\0';  // line 19: 手动添加终止符
    
    buf->valid = 1;
    return 0;
}

void execute_firmware_update(CommandBuffer *buf) {
    char *update_data = NULL;
    size_t data_size = 0;
    
    // line 27: 分配堆内存
    update_data = (char *)malloc(MAX_RESP_LEN);
    if (update_data == NULL) {
        buf->valid = 0;
        return;
    }
    
    // line 33: 模拟固件更新数据处理
    snprintf(update_data, MAX_RESP_LEN, "Processing: %s", buf->command);
    
    // line 36: 处理完成后立即释放
    free(update_data);
    update_data = NULL;  // line 38: 置NULL防止悬垂指针
    
    // line 40: 使用局部变量存储响应，避免堆内存管理
    char local_response[MAX_RESP_LEN];
    snprintf(local_response, sizeof(local_response), "Done: %s", buf->command);
    strncpy(buf->response, local_response, MAX_RESP_LEN - 1);
    buf->response[MAX_RESP_LEN - 1] = '\0';
}

int main() {
    CommandBuffer buf = {0};
    const char *user_input = "TEST_CMD_123";
    
    if (process_command(&buf, user_input, strlen(user_input)) == 0) {
        execute_firmware_update(&buf);
        if (buf.valid) {
            printf("%s\n", buf.response);
        }
    }
    
    return 0;
}

