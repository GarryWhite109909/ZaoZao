#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_BUF_SIZE 64

typedef struct {
    char data[MAX_BUF_SIZE];
    uint8_t len;
} Packet;

// Line 12: Parse a fixed-length packet from UART buffer
int parse_uart_packet(const uint8_t *uart_buf, size_t uart_len, Packet *out) {
    if (uart_buf == NULL || out == NULL) {
        return -1;
    }
    
    // Line 17: Validate input length against destination buffer size
    if (uart_len >= MAX_BUF_SIZE) {
        return -2;
    }
    
    // Line 21: Bounded copy - uart_len is guaranteed < MAX_BUF_SIZE
    memcpy(out->data, uart_buf, uart_len);
    out->data[uart_len] = '\0';
    out->len = (uint8_t)uart_len;
    return 0;
}

// Line 27: Process command from UART with defensive allocation
int process_uart_command(const uint8_t *cmd, size_t cmd_len) {
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (pkt == NULL) {
        return -1;
    }
    
    // Line 33: Check return value of parse function
    int ret = parse_uart_packet(cmd, cmd_len, pkt);
    if (ret != 0) {
        free(pkt);
        pkt = NULL;  // Line 37: Set to NULL after free to prevent double-free
        return ret;
    }
    
    // Line 40: Safe string handling - pkt->data is null-terminated
    printf("Command: %s\n", pkt->data);
    
    free(pkt);
    pkt = NULL;  // Line 44: Consistent NULL assignment after free
    return 0;
}

// Line 48: Main UART dispatch - entry point from interrupt handler
int uart_dispatch(const uint8_t *rx_buffer, size_t rx_len) {
    if (rx_buffer == NULL || rx_len == 0) {
        return -1;
    }
    
    // Line 53: Upper bound check before calling processing
    if (rx_len > MAX_BUF_SIZE) {
        return -2;
    }
    
    return process_uart_command(rx_buffer, rx_len);
}

int main(void) {
    // Simulated UART data (from hardware)
    uint8_t test_data[] = "SET_TEMP 25";
    int result = uart_dispatch(test_data, strlen((char *)test_data));
    return result;
}

