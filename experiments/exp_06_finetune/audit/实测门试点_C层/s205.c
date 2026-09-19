#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_FRAME_LEN 128
#define HDR_LEN 8
#define PAYLOAD_MAX 120

typedef struct {
    uint8_t data[MAX_FRAME_LEN];
    uint16_t len;
} frame_t;

static int parse_frame(const uint8_t *buf, uint16_t buf_len, frame_t *out) {
    if (buf_len < HDR_LEN) {
        return -1;
    }
    uint16_t payload_len = (buf[4] << 8) | buf[5];
    if (payload_len > PAYLOAD_MAX) {
        payload_len = PAYLOAD_MAX;
    }
    if (payload_len + HDR_LEN > buf_len) {
        return -1;
    }
    memcpy(out->data, buf, HDR_LEN);
    memcpy(out->data + HDR_LEN, buf + HDR_LEN, payload_len);
    out->len = HDR_LEN + payload_len;
    return 0;
}

int process_network_frame(const uint8_t *raw, uint16_t raw_len) {
    frame_t frame;
    memset(&frame, 0, sizeof(frame));
    
    if (parse_frame(raw, raw_len, &frame) != 0) {
        return -1;
    }
    
    uint8_t local_buf[64];
    memcpy(local_buf, frame.data, frame.len);
    
    uint16_t opcode = (local_buf[0] << 8) | local_buf[1];
    if (opcode == 0x01) {
        printf("Handle opcode 0x01\n");
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        return 1;
    }
    uint8_t input[256];
    size_t n = fread(input, 1, sizeof(input), fp);
    fclose(fp);
    if (n > MAX_FRAME_LEN) {
        n = MAX_FRAME_LEN;
    }
    process_network_frame(input, (uint16_t)n);
    return 0;
}

