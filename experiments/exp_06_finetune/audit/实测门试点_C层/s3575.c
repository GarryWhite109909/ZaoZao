#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_LEN 128
#define MAX_HEADER_LEN 8

typedef struct {
    char header[MAX_HEADER_LEN];
    char payload[MAX_PKT_LEN];
    size_t payload_len;
} packet_t;

/* 安全解析：跨函数传递缓冲区，但通过显式长度参数限制写入 */
static int parse_packet(const char *raw, size_t raw_len, char *out, size_t out_cap) {
    if (raw == NULL || out == NULL) {
        return -1;
    }
    if (raw_len > MAX_PKT_LEN) {
        return -2;
    }

    /* line 18: 边界检查 - 确保 out_cap 足够容纳 header + payload */
    if (out_cap < MAX_HEADER_LEN + MAX_PKT_LEN) {
        return -3;
    }

    /* 先复制 header，长度固定为 MAX_HEADER_LEN */
    memcpy(out, raw, MAX_HEADER_LEN);
    /* 再复制 payload，长度受限 */
    memcpy(out + MAX_HEADER_LEN, raw + MAX_HEADER_LEN, raw_len - MAX_HEADER_LEN);

    return 0;
}

/* 主处理函数：使用堆缓冲区，并在 free 后置 NULL */
int process_packet(const char *input, size_t input_len) {
    packet_t *pkt = NULL;
    char *buf = NULL;

    if (input == NULL || input_len < MAX_HEADER_LEN) {
        return -1;
    }

    /* 分配固定大小缓冲区，避免栈溢出 */
    buf = (char *)malloc(MAX_HEADER_LEN + MAX_PKT_LEN);
    if (buf == NULL) {
        return -2;
    }

    /* 调用解析函数，传入实际容量 */
    if (parse_packet(input, input_len, buf, MAX_HEADER_LEN + MAX_PKT_LEN) != 0) {
        free(buf);
        buf = NULL;  /* line 49: free 后置 NULL，防止悬垂指针 */
        return -3;
    }

    /* 模拟固件中的后续处理 */
    pkt = (packet_t *)buf;
    pkt->payload_len = input_len - MAX_HEADER_LEN;
    printf("Processed packet: payload_len=%zu\n", pkt->payload_len);

    /* 释放并置 NULL */
    free(buf);
    buf = NULL;  /* line 59: 二次 free 保护 */

    return 0;
}

int main(int argc, char *argv[]) {
    /* 测试用例：正常输入 */
    char test_data[MAX_PKT_LEN] = {0};
    memset(test_data, 'A', sizeof(test_data));
    process_packet(test_data, sizeof(test_data));

    /* 测试用例：过短输入（应被拒绝） */
    process_packet(test_data, 4);

    /* 测试用例：NULL 输入（应被拒绝） */
    process_packet(NULL, 10);

    return 0;
}

