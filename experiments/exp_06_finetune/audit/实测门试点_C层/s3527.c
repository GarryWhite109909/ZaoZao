#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PKT_SIZE 256
#define MAX_HEADER_SIZE 16

typedef struct {
    unsigned char data[MAX_PKT_SIZE];
    size_t len;
} packet_t;

static int parse_header(const unsigned char *buf, size_t buf_len, size_t *payload_offset) {
    if (buf_len < MAX_HEADER_SIZE) {
        return -1;
    }
    /* Validate header magic bytes */
    if (buf[0] != 0xAA || buf[1] != 0x55) {
        return -1;
    }
    *payload_offset = MAX_HEADER_SIZE;
    return 0;
}

static int process_packet(packet_t *pkt, unsigned char *out_buf, size_t out_cap) {
    size_t payload_offset = 0;
    size_t payload_len;

    if (parse_header(pkt->data, pkt->len, &payload_offset) != 0) {
        return -1;
    }

    payload_len = pkt->len - payload_offset;  /* line 27 */
    if (payload_len > out_cap) {
        return -1;
    }

    memcpy(out_buf, pkt->data + payload_offset, payload_len);  /* line 31 */
    return (int)payload_len;
}

int main(void) {
    unsigned char raw_data[MAX_PKT_SIZE] = {0xAA, 0x55, 0x01, 0x02, 0x03, 0x04};
    unsigned char output[64] = {0};
    packet_t pkt;
    int ret;

    pkt.len = 6;
    memcpy(pkt.data, raw_data, pkt.len);

    ret = process_packet(&pkt, output, sizeof(output));
    if (ret < 0) {
        return 1;
    }

    printf("Processed %d bytes\n", ret);
    return 0;
}

