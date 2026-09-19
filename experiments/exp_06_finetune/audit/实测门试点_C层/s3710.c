#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define MAX_HEADER_SIZE 64

typedef struct {
    uint8_t *data;
    size_t len;
} packet_t;

typedef struct {
    char *header_str;
    size_t header_len;
} parsed_header_t;

// Parse packet header, returns 0 on success, -1 on error
static int parse_header(packet_t *pkt, parsed_header_t *out) {
    if (pkt == NULL || out == NULL || pkt->data == NULL) {
        return -1;
    }
    if (pkt->len < MAX_HEADER_SIZE) {
        return -1;
    }
    
    // Extract header as string (bounded copy)
    out->header_str = (char *)malloc(MAX_HEADER_SIZE);
    if (out->header_str == NULL) {
        return -1;
    }
    memcpy(out->header_str, pkt->data, MAX_HEADER_SIZE - 1);
    out->header_str[MAX_HEADER_SIZE - 1] = '\0';
    out->header_len = MAX_HEADER_SIZE - 1;
    return 0;
}

// Process network packet, returns 0 on success, -1 on error
static int process_packet(packet_t *pkt) {
    parsed_header_t header;
    memset(&header, 0, sizeof(header));
    
    if (parse_header(pkt, &header) != 0) {
        return -1;
    }
    
    // Validate header content before use
    if (header.header_str[0] != 'P') {
        free(header.header_str);
        header.header_str = NULL;
        return -1;
    }
    
    // Use parsed header (simulate processing)
    printf("Processing header: %s\n", header.header_str);
    
    // Safe cleanup: free and NULL the pointer
    free(header.header_str);
    header.header_str = NULL;
    
    // Double-free protection: second free is safe because pointer is NULL
    free(header.header_str);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <packet_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    
    // Read packet data with size check
    packet_t pkt;
    pkt.data = (uint8_t *)malloc(MAX_PKT_SIZE);
    if (pkt.data == NULL) {
        fclose(fp);
        return 1;
    }
    
    pkt.len = fread(pkt.data, 1, MAX_PKT_SIZE, fp);
    fclose(fp);
    
    if (pkt.len == 0) {
        free(pkt.data);
        pkt.data = NULL;
        return 1;
    }
    
    int ret = process_packet(&pkt);
    
    // Cleanup main packet
    free(pkt.data);
    pkt.data = NULL;
    
    return ret;
}

