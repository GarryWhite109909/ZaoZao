#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buffer;
    int length;
} Packet;

Packet *parse_packet(const char *data, int size) {
    if (size < 4) return NULL;
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) return NULL;
    pkt->length = size;
    pkt->buffer = (char *)malloc(size);
    if (!pkt->buffer) {
        free(pkt);
        return NULL;
    }
    memcpy(pkt->buffer, data, size);
    return pkt;
}

void process_packet(Packet *pkt) {
    if (!pkt || !pkt->buffer) return;
    if (pkt->length > 0) {
        printf("First byte: 0x%02x\n", (unsigned char)pkt->buffer[0]);
    }
    free(pkt->buffer);
    // 缺少 pkt->buffer = NULL; 且未释放 pkt
    free(pkt);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    Packet *p = parse_packet(argv[1], (int)strlen(argv[1]));
    if (!p) return 1;
    process_packet(p);
    // 此处 p 已被释放，但 p 指针本身仍指向已释放内存
    if (p->length > 0) {  // UAF: p 悬垂指针
        printf("Length: %d\n", p->length);
    }
    return 0;
}

