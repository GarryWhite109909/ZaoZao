#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
} buffer_t;

static void buffer_free(buffer_t *buf) {
    if (buf) {
        free(buf->data);
        buf->data = NULL;  // line 12: NULL after free
        buf->len = 0;
    }
}

static int process_packet(buffer_t *buf, const uint8_t *payload, size_t payload_len) {
    if (!buf || !payload || payload_len > 1024) {
        return -1;
    }
    
    buf->data = (uint8_t *)malloc(payload_len);
    if (!buf->data) {
        return -1;
    }
    buf->len = payload_len;
    memcpy(buf->data, payload, payload_len);
    
    // Simulate processing that may fail
    if (payload[0] == 0xFF) {
        buffer_free(buf);  // line 27: frees and NULLs
        return -2;
    }
    
    return 0;
}

static int handle_command(buffer_t *rx_buf, const uint8_t *cmd, size_t cmd_len) {
    if (process_packet(rx_buf, cmd, cmd_len) != 0) {
        return -1;
    }
    
    // Use rx_buf->data safely here
    uint8_t checksum = 0;
    for (size_t i = 0; i < rx_buf->len; i++) {
        checksum ^= rx_buf->data[i];
    }
    
    // line 42: buffer_free NULLs data, preventing double-free
    buffer_free(rx_buf);
    return checksum;
}

int main(void) {
    buffer_t rx = {0};
    uint8_t test_cmd[] = {0x01, 0x02, 0x03};
    
    int result = handle_command(&rx, test_cmd, sizeof(test_cmd));
    printf("Result: %d\n", result);
    
    // line 53: rx.data is NULL, safe to call again
    buffer_free(&rx);
    return 0;
}

