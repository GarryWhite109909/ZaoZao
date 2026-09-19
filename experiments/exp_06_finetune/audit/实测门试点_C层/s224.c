#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_CMD_LEN 64
#define MAX_RESP_LEN 128

typedef struct {
    uint8_t header[4];
    uint8_t payload[128];
} can_frame_t;

void process_can_message(const can_frame_t *frame, uint8_t *response_buf)
{
    uint8_t cmd[MAX_CMD_LEN];
    uint8_t resp[MAX_RESP_LEN];
    uint8_t payload_len;
    uint8_t i;

    payload_len = frame->payload[0];

    if (payload_len > MAX_CMD_LEN) {
        payload_len = MAX_CMD_LEN;
    }

    for (i = 0; i < payload_len; i++) {
        cmd[i] = frame->payload[i + 1];
    }

    /* 模拟命令处理：复制响应 */
    for (i = 0; i < payload_len; i++) {
        resp[i] = cmd[i] ^ 0x5A;
    }

    memcpy(response_buf, resp, payload_len);
}

int main(void)
{
    can_frame_t frame;
    uint8_t response[MAX_RESP_LEN];

    memset(&frame, 0, sizeof(frame));
    frame.payload[0] = 200;  /* 超出 cmd 缓冲区但被截断 */

    for (int i = 1; i <= 64; i++) {
        frame.payload[i] = (uint8_t)i;
    }

    process_can_message(&frame, response);
    printf("Response processed: %d bytes\n", (int)frame.payload[0]);
    return 0;
}

