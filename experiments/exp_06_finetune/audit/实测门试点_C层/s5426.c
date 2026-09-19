#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_DATA_SIZE 256
#define FIRMWARE_HEADER_SIZE 4

typedef struct {
    uint8_t magic[2];
    uint16_t data_len;
} firmware_header_t;

static uint8_t *firmware_data = NULL;
static uint32_t firmware_size = 0;

int parse_firmware(const uint8_t *buffer, uint32_t buffer_size) {
    firmware_header_t header;
    
    if (buffer == NULL || buffer_size < FIRMWARE_HEADER_SIZE) {
        return -1;
    }
    
    memcpy(&header, buffer, FIRMWARE_HEADER_SIZE);
    
    if (header.magic[0] != 0xAA || header.magic[1] != 0x55) {
        return -2;
    }
    
    if (header.data_len > MAX_DATA_SIZE) {
        return -3;
    }
    
    if (header.data_len > buffer_size - FIRMWARE_HEADER_SIZE) {
        return -4;
    }
    
    if (firmware_data != NULL) {
        free(firmware_data);
        firmware_data = NULL;
    }
    
    firmware_data = (uint8_t *)malloc(header.data_len);
    if (firmware_data == NULL) {
        return -5;
    }
    
    memcpy(firmware_data, buffer + FIRMWARE_HEADER_SIZE, header.data_len);
    firmware_size = header.data_len;
    
    return 0;
}

void clear_firmware(void) {
    if (firmware_data != NULL) {
        free(firmware_data);
        firmware_data = NULL;
    }
    firmware_size = 0;
}

int main(void) {
    uint8_t test_buffer[64] = {0xAA, 0x55, 0x10, 0x00};
    
    if (parse_firmware(test_buffer, sizeof(test_buffer)) == 0) {
        printf("Firmware loaded, size: %u\n", firmware_size);
    }
    
    clear_firmware();
    return 0;
}

