#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_LEN 256
#define MAX_CMD_LEN 32

typedef struct {
    uint8_t data[MAX_PKT_LEN];
    uint16_t len;
} packet_t;

static int parse_command(const uint8_t *buf, uint16_t len, char *cmd_out, size_t cmd_cap) {
    if (buf == NULL || cmd_out == NULL) {
        return -1;
    }
    if (len > MAX_PKT_LEN) {
        return -2;
    }
    
    /* Extract command field (first 4 bytes as length-prefixed string) */
    uint16_t cmd_len = (uint16_t)((buf[0] << 8) | buf[1]);
    if (cmd_len == 0 || cmd_len > MAX_CMD_LEN - 1) {
        return -3;
    }
    if (cmd_len > len - 2) {
        return -4;
    }
    
    /* Bounds-checked copy into caller-provided buffer */
    if (cmd_len >= cmd_cap) {
        return -5;
    }
    memcpy(cmd_out, buf + 2, cmd_len);
    cmd_out[cmd_len] = '\0';
    return 0;
}

int process_packet(const packet_t *pkt) {
    if (pkt == NULL) {
        return -1;
    }
    
    char cmd[MAX_CMD_LEN] = {0};
    int ret = parse_command(pkt->data, pkt->len, cmd, sizeof(cmd));
    if (ret != 0) {
        return ret;
    }
    
    /* Command dispatch with exact match (no unsafe strcpy/strcat) */
    if (strcmp(cmd, "STATUS") == 0) {
        printf("Firmware v1.2.3\n");
    } else if (strcmp(cmd, "RESET") == 0) {
        printf("Resetting...\n");
    } else {
        printf("Unknown cmd: %s\n", cmd);
    }
    return 0;
}

int main(void) {
    packet_t pkt = {.len = 0};
    
    /* Simulated network receive with length validation */
    size_t recv_len = fread(pkt.data, 1, MAX_PKT_LEN, stdin);
    if (recv_len == 0 || recv_len > MAX_PKT_LEN) {
        return -1;
    }
    pkt.len = (uint16_t)recv_len;
    
    return process_packet(&pkt);
}

