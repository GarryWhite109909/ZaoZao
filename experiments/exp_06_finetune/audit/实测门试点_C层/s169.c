#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 64
#define CMD_HEADER 4
#define SAFE_COPY(dst, src, sz) do { \
    strncpy((dst), (src), (sz) - 1); \
    (dst)[(sz) - 1] = '\0'; \
} while (0)

typedef struct {
    char header[CMD_HEADER];
    char payload[128];
    int len;
} Packet;

int process_packet(Packet *pkt, char *out, int out_sz) {
    if (pkt->len <= 0 || pkt->len > 128) {
        return -1;
    }
    
    /* line 20: 直接使用外部传入的 out_sz，未做非零校验 */
    if (out_sz > 0) {
        /* line 23: 跨宏调用 strncpy，但宏基于 strncpy 实现 */
        SAFE_COPY(out, pkt->payload, out_sz);
        return 0;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    Packet pkt;
    char response[32];
    char *heap_buf = NULL;
    
    memset(&pkt, 0, sizeof(pkt));
    pkt.len = 100;
    memcpy(pkt.payload, "A", 1);
    
    /* line 38: 栈缓冲区只有 32 字节 */
    if (process_packet(&pkt, response, sizeof(response)) == 0) {
        printf("Response: %s\n", response);
    }
    
    /* line 42: 分配 64 字节 */
    heap_buf = (char *)malloc(MAX_BUF);
    if (!heap_buf) return 1;
    
    /* line 45: 传入 128 字节大小，超过实际 64 字节 */
    if (process_packet(&pkt, heap_buf, 128) == 0) {
        printf("Heap response: %s\n", heap_buf);
    }
    
    free(heap_buf);
    return 0;
}

