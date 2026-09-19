#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define MAX_HEADER_LEN 64
#define SAFE_FREE(p) do { if(p) { free(p); (p)=NULL; } } while(0)

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t data[];
} __attribute__((packed)) PacketHeader;

static int parse_and_process(const uint8_t *buf, size_t buf_len) {
    if (buf_len < sizeof(PacketHeader)) {
        return -1;
    }
    
    PacketHeader hdr;
    memcpy(&hdr, buf, sizeof(PacketHeader));
    hdr.len = ntohs(hdr.len);
    
    if (hdr.len > MAX_PKT_SIZE || hdr.len > buf_len - sizeof(PacketHeader)) {
        return -1;
    }
    
    uint8_t *payload_copy = (uint8_t *)malloc(hdr.len + 1);
    if (!payload_copy) {
        return -1;
    }
    memcpy(payload_copy, buf + sizeof(PacketHeader), hdr.len);
    payload_copy[hdr.len] = '\0';
    
    char output[128];
    snprintf(output, sizeof(output), "Processing packet type %u, payload: %.64s",
             hdr.type, payload_copy);
    
    SAFE_FREE(payload_copy);
    printf("%s\n", output);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <packet_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    uint8_t buffer[MAX_PKT_SIZE];
    size_t nread = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (nread == 0) {
        return 1;
    }
    
    return parse_and_process(buffer, nread);
}

