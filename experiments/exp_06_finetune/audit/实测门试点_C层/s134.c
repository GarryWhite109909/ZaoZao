#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_CMD_LEN 128
#define MAX_RESP_LEN 256

/* 固件命令处理结构体 */
typedef struct {
    char cmd_buf[MAX_CMD_LEN];
    uint8_t resp[MAX_RESP_LEN];
    uint16_t resp_len;
    uint8_t error;
} fw_cmd_t;

/* 远程命令响应缓冲区（全局，模拟共享内存） */
static uint8_t g_shared_resp[MAX_RESP_LEN];

/* 从共享缓冲区拷贝响应到本地 */
static void copy_response(fw_cmd_t *cmd, const uint8_t *src, uint16_t len) {
    // 漏洞点：未校验 len 是否超过 cmd->resp 的容量（MAX_RESP_LEN）
    memcpy(cmd->resp, src, len);
    cmd->resp_len = len;
}

/* 解析固件升级包头部，提取响应数据长度 */
static uint16_t parse_upgrade_header(const uint8_t *pkt) {
    // 模拟从网络包中解析出的长度字段（攻击者可控）
    uint16_t len = (pkt[0] << 8) | pkt[1];
    return len;
}

/* 处理固件升级命令（跨函数调用链） */
void handle_fw_upgrade(const uint8_t *pkt, uint16_t pkt_len) {
    fw_cmd_t cmd;
    uint16_t resp_len;

    memset(&cmd, 0, sizeof(cmd));

    // 第一步：解析包头获取响应长度（攻击者控制）
    resp_len = parse_upgrade_header(pkt);

    // 第二步：将共享缓冲区内容拷贝到栈上结构体（栈溢出触发点）
    // 攻击者控制 resp_len 为 0xFFFF，而 cmd.resp 只有 256 字节
    copy_response(&cmd, g_shared_resp, resp_len);

    // 第三步：后续处理（此处省略，实际固件会基于 cmd.resp 执行操作）
    if (cmd.resp_len > 0) {
        printf("Firmware upgrade response: %u bytes\n", cmd.resp_len);
    }
}

/* 模拟网络接收入口 */
void process_packet(const uint8_t *packet, uint16_t size) {
    if (size >= 2) {
        handle_fw_upgrade(packet, size);
    }
}

int main() {
    // 模拟一个畸形包：长度字段为 0xFFFF（65535），远超栈缓冲区
    uint8_t malicious_pkt[2] = {0xFF, 0xFF};
    process_packet(malicious_pkt, sizeof(malicious_pkt));
    return 0;
}

