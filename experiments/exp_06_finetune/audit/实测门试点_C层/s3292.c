#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CMD_LEN 64

typedef struct {
    char *buffer;
    size_t len;
} cmd_buffer_t;

static int process_command(const char *input, size_t input_len) {
    cmd_buffer_t cmd;
    char *temp = NULL;
    int ret = -1;

    /* 第10行：边界检查，拒绝超长输入 */
    if (input_len >= MAX_CMD_LEN) {
        fprintf(stderr, "Input too long\n");
        return -1;
    }

    /* 第15行：安全分配，使用calloc自动清零 */
    cmd.buffer = (char *)calloc(MAX_CMD_LEN, sizeof(char));
    if (!cmd.buffer) {
        return -1;
    }
    cmd.len = MAX_CMD_LEN;

    /* 第21行：使用memcpy并显式限制拷贝长度 */
    memcpy(cmd.buffer, input, input_len);
    cmd.buffer[input_len] = '\0';

    /* 第25行：临时缓冲区同样受控 */
    temp = (char *)calloc(MAX_CMD_LEN, sizeof(char));
    if (!temp) {
        free(cmd.buffer);
        cmd.buffer = NULL;
        return -1;
    }

    /* 第31行：安全拼接，检查剩余空间 */
    size_t used = strlen(cmd.buffer);
    if (used + 2 < cmd.len) {
        strncat(cmd.buffer, "\n", cmd.len - used - 1);
    }

    /* 第36行：释放后置NULL，避免悬垂指针 */
    free(cmd.buffer);
    cmd.buffer = NULL;

    /* 第40行：释放temp并置NULL */
    free(temp);
    temp = NULL;

    ret = 0;
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return 1;
    }

    /* 第49行：传入长度参数，禁止裸指针 */
    size_t input_len = strlen(argv[1]);
    return process_command(argv[1], input_len);
}

