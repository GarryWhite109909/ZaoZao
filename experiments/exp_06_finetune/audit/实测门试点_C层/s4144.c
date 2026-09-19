#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t *cursor;
} Packet;

void packet_free(Packet *pkt) {
    if (pkt->data) {
        free(pkt->data);
        pkt->data = NULL;       // line 12: 防御1 - free后置NULL
    }
    pkt->len = 0;
    pkt->cursor = NULL;         // line 15: 防御2 - 同步失效游标
}

int parse_frame(Packet *pkt, uint8_t *out, size_t out_size) {
    if (pkt->cursor == NULL || pkt->data == NULL) {  // line 18: 入口空指针检查
        return -1;
    }
    
    size_t remaining = pkt->len - (pkt->cursor - pkt->data);
    if (remaining < 4) {         // line 22: 边界检查 - 帧头长度
        return -1;
    }
    
    uint16_t payload_len = (pkt->cursor[0] << 8) | pkt->cursor[1];
    if (payload_len > remaining - 2) {  // line 26: 边界检查 - 载荷长度
        return -1;
    }
    
    if (payload_len > out_size) {       // line 29: 边界检查 - 输出缓冲区
        return -1;
    }
    
    memcpy(out, pkt->cursor + 2, payload_len);  // line 32: 安全拷贝
    pkt->cursor += 2 + payload_len;
    return payload_len;
}

int process_packet(Packet *pkt) {
    uint8_t frame[256];
    int ret = parse_frame(pkt, frame, sizeof(frame));  // line 39: 栈缓冲区
    if (ret < 0) {
        return -1;
    }
    // 模拟帧处理
    return ret;
}

int main(void) {
    Packet pkt = {0};
    pkt.data = malloc(1024);
    if (!pkt.data) return 1;
    pkt.len = 1024;
    pkt.cursor = pkt.data;
    
    // 填充模拟数据
    pkt.data[0] = 0x00; pkt.data[1] = 0x10;  // payload_len = 16
    memset(pkt.data + 2, 0xAB, 16);
    
    process_packet(&pkt);
    packet_free(&pkt);
    
    // 后续使用已释放对象 - 防御验证点
    if (pkt.data != NULL) {     // line 62: 防御3 - 使用前检查
        process_packet(&pkt);   // 不会执行，因为data为NULL
    }
    return 0;
}

