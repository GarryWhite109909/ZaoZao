#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 256
#define MAX_HEADER_LEN 16
#define MAX_PAYLOAD_LEN (MAX_PKT_LEN - MAX_HEADER_LEN)

typedef struct {
    uint8_t header[MAX_HEADER_LEN];
    uint8_t payload[MAX_PAYLOAD_LEN];
    uint16_t payload_len;
} packet_t;

static int parse_header(const uint8_t *buf, size_t buf_len, uint16_t *payload_len) {
    if (buf_len < MAX_HEADER_LEN) {
        return -1;
    }
    /* Header layout: [0..1] = payload length (big-endian) */
    *payload_len = (uint16_t)((buf[0] << 8) | buf[1]);
    if (*payload_len > MAX_PAYLOAD_LEN) {
        return -1;
    }
    return 0;
}

static void process_packet(packet_t *pkt, const uint8_t *raw, size_t raw_len) {
    uint16_t payload_len = 0;
    if (parse_header(raw, raw_len, &payload_len) != 0) {
        return;
    }
    pkt->payload_len = payload_len;
    /* Boundary check: copy exactly payload_len bytes into fixed-size array */
    memcpy(pkt->payload, raw + MAX_HEADER_LEN, payload_len);
}

int main(void) {
    uint8_t raw[MAX_PKT_LEN];
    size_t raw_len = 0;
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* Simulate receiving a packet from network */
    raw[0] = 0x00;
    raw[1] = 0x40;  /* payload_len = 64 */
    memcpy(raw + MAX_HEADER_LEN, "A", 64);
    raw_len = MAX_HEADER_LEN + 64;

    process_packet(&pkt, raw, raw_len);

    /* Safe: no heap allocation, stack arrays are fixed-size */
    printf("Processed payload_len=%u\n", pkt.payload_len);
    return 0;
}

