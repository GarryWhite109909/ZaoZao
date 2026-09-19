#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_LEN 128
#define MAX_CMD_LEN  64

typedef struct {
    char cmd[MAX_CMD_LEN];
    size_t len;
} packet_t;

static int validate_packet(const packet_t *pkt) {
    if (pkt->len == 0 || pkt->len >= MAX_CMD_LEN) {
        return -1;
    }
    if (pkt->cmd[pkt->len - 1] != '\n') {
        return -1;
    }
    return 0;
}

static void process_packet(const packet_t *pkt) {
    char *buf = (char *)malloc(MAX_PKT_LEN);
    if (!buf) {
        return;
    }
    
    size_t copy_len = pkt->len < MAX_PKT_LEN ? pkt->len : MAX_PKT_LEN;
    memcpy(buf, pkt->cmd, copy_len);
    buf[copy_len] = '\0';
    
    printf("Processing: %s", buf);
    free(buf);
    buf = NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        return 1;
    }
    
    packet_t pkt;
    size_t read_len = fread(&pkt, 1, sizeof(packet_t), fp);
    fclose(fp);
    
    if (read_len != sizeof(packet_t)) {
        return 1;
    }
    
    if (validate_packet(&pkt) != 0) {
        return 1;
    }
    
    process_packet(&pkt);
    return 0;
}

