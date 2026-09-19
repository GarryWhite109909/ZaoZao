#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF_SIZE 128
#define MAX_CMD_LEN   64

typedef struct {
    uint8_t data[MAX_BUF_SIZE];
    uint16_t len;
    uint8_t valid;
} packet_t;

static uint8_t cmd_buf[MAX_CMD_LEN];

void parse_packet(packet_t *pkt) {
    if (pkt->valid == 0) {
        return;
    }
    if (pkt->len > MAX_BUF_SIZE) {
        pkt->len = MAX_BUF_SIZE;
    }
    memcpy(cmd_buf, pkt->data, pkt->len);
}

int process_command(uint8_t *cmd, uint16_t cmd_len) {
    if (cmd_len > MAX_CMD_LEN) {
        return -1;
    }
    memcpy(cmd_buf, cmd, cmd_len);
    if (cmd_buf[0] == 0xAA) {
        printf("Command accepted\n");
        return 0;
    }
    return -2;
}

int main(void) {
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.len = 200;
    pkt.valid = 1;
    parse_packet(&pkt);
    process_command(cmd_buf, pkt.len);
    return 0;
}

