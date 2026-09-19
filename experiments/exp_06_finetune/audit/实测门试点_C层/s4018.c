#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKET_SIZE 1024
#define HEADER_SIZE 8

typedef struct {
    char *payload;
    int payload_len;
} Packet;

typedef struct {
    char *data;
    int len;
} Buffer;

/* Parse packet header and allocate payload buffer */
Buffer *parse_packet(const char *raw, int raw_len) {
    if (raw == NULL || raw_len < HEADER_SIZE) {
        return NULL;
    }

    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (buf == NULL) {
        return NULL;
    }

    /* Extract payload length from header (big-endian) */
    int payload_len = (raw[4] << 24) | (raw[5] << 16) | (raw[6] << 8) | raw[7];
    if (payload_len <= 0 || payload_len > MAX_PACKET_SIZE) {
        free(buf);
        return NULL;
    }

    if (raw_len < HEADER_SIZE + payload_len) {
        free(buf);
        return NULL;
    }

    buf->data = (char *)malloc(payload_len);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }

    memcpy(buf->data, raw + HEADER_SIZE, payload_len);
    buf->len = payload_len;
    return buf;
}

/* Process packet and return result */
int process_packet(const char *raw, int raw_len) {
    Buffer *buf = parse_packet(raw, raw_len);
    if (buf == NULL) {
        return -1;
    }

    /* Simulate processing */
    int result = 0;
    for (int i = 0; i < buf->len; i++) {
        if (buf->data[i] == '\0') {
            result = 1;
            break;
        }
    }

    /* Free buffer and set pointer to NULL to prevent double-free */
    free(buf->data);
    buf->data = NULL;
    free(buf);
    buf = NULL;

    /* After free, buffer is no longer used - safe */
    return result;
}

int main() {
    char raw[MAX_PACKET_SIZE + HEADER_SIZE];
    int raw_len = HEADER_SIZE + 10;
    memset(raw, 'A', raw_len);

    int result = process_packet(raw, raw_len);
    printf("Result: %d\n", result);
    return 0;
}

