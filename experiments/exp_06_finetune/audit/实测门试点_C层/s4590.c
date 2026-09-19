#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 128

typedef struct {
    char buffer[MAX_BUF];
    size_t len;
} Packet;

int process_packet(Packet *pkt, const char *data, size_t data_len) {
    if (data_len > MAX_BUF - 1) {
        return -1;
    }
    
    memcpy(pkt->buffer, data, data_len);
    pkt->buffer[data_len] = '\0';
    pkt->len = data_len;
    return 0;
}

void parse_command(Packet *pkt) {
    char *cmd = (char *)malloc(MAX_BUF);
    if (cmd == NULL) {
        return;
    }
    
    strcpy(cmd, pkt->buffer);
    
    if (strncmp(cmd, "SET", 3) == 0) {
        printf("Command: %s\n", cmd);
    }
    
    free(cmd);
    cmd = NULL;
}

int main(void) {
    Packet pkt;
    char input[MAX_BUF];
    
    printf("Enter data: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }
    
    size_t input_len = strlen(input);
    if (input_len > 0 && input[input_len - 1] == '\n') {
        input[input_len - 1] = '\0';
        input_len--;
    }
    
    if (process_packet(&pkt, input, input_len) != 0) {
        printf("Error: data too long\n");
        return 1;
    }
    
    parse_command(&pkt);
    return 0;
}

