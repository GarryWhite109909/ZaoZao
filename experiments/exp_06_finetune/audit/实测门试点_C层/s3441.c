#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_LEN 256
#define MAX_CMD_LEN 64

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} Buffer;

static int process_command(const char *cmd, size_t cmd_len) {
    char local_buf[MAX_CMD_LEN];
    
    // Line 12: Bounds check before any copy operation
    if (cmd_len >= MAX_CMD_LEN) {
        return -1;
    }
    
    // Line 16: Safe copy - length verified against destination capacity
    memcpy(local_buf, cmd, cmd_len);
    local_buf[cmd_len] = '\0';
    
    // Simulate command processing
    if (strncmp(local_buf, "ping", 4) == 0) {
        printf("PONG\n");
    }
    return 0;
}

static int handle_packet(const uint8_t *pkt, size_t pkt_len) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (!buf) {
        return -1;
    }
    
    // Line 28: Initialize all fields before use
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
    
    // Line 32: Validate input length against protocol maximum
    if (pkt_len > MAX_PKT_LEN) {
        free(buf);
        return -2;
    }
    
    // Line 36: Allocate exact needed size plus null terminator
    buf->data = malloc(pkt_len + 1);
    if (!buf->data) {
        free(buf);
        return -3;
    }
    buf->cap = pkt_len + 1;
    
    // Line 42: Copy with verified length
    memcpy(buf->data, pkt, pkt_len);
    buf->data[pkt_len] = '\0';
    buf->len = pkt_len;
    
    // Line 46: Extract command from packet (first field)
    char *cmd_start = strchr((char *)buf->data, ':');
    if (cmd_start) {
        cmd_start++;  // Skip colon
        size_t cmd_len = buf->len - (cmd_start - (char *)buf->data);
        // Line 51: Length derived from actual buffer content
        if (cmd_len > 0) {
            process_command(cmd_start, cmd_len);
        }
    }
    
    // Line 55: Cleanup - free and nullify pointer
    free(buf->data);
    buf->data = NULL;
    free(buf);
    buf = NULL;
    
    return 0;
}

int main(int argc, char **argv) {
    // Test harness - simulates network receive
    uint8_t test_pkt[] = "CMD:ping";
    handle_packet(test_pkt, sizeof(test_pkt) - 1);
    return 0;
}

