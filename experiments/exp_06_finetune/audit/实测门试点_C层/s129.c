#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CMD_LEN 128

typedef struct {
    char cmd_buf[MAX_CMD_LEN];
    int len;
} cmd_packet_t;

static int parse_packet(const char *input, cmd_packet_t *pkt) {
    size_t input_len = strlen(input);
    if (input_len > MAX_CMD_LEN) {
        return -1;
    }
    memcpy(pkt->cmd_buf, input, input_len);
    pkt->len = (int)input_len;
    pkt->cmd_buf[pkt->len] = '\0';
    return 0;
}

static void process_command(const char *raw_data) {
    cmd_packet_t pkt;
    char response[64];
    
    if (parse_packet(raw_data, &pkt) != 0) {
        printf("Invalid packet\n");
        return;
    }

    if (strncmp(pkt.cmd_buf, "STATUS", 6) == 0) {
        snprintf(response, sizeof(response), "Device status: OK");
    } else if (strncmp(pkt.cmd_buf, "RESET", 5) == 0) {
        snprintf(response, sizeof(response), "Resetting device...");
    } else {
        snprintf(response, sizeof(response), "Unknown command");
    }
    printf("%s\n", response);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command>\n", argv[0]);
        return 1;
    }
    process_command(argv[1]);
    return 0;
}

