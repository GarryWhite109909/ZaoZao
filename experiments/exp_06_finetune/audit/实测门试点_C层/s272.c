#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PKT_LEN 4096
#define HDR_LEN 24
#define MAX_OPTS 8

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t data[];
} __attribute__((packed)) pkt_opt_t;

typedef struct {
    uint32_t magic;
    uint16_t opt_count;
    uint16_t flags;
    uint8_t reserved[16];
} __attribute__((packed)) pkt_hdr_t;

static int parse_options(const uint8_t *buf, size_t buf_len, uint32_t *opts_out) {
    const pkt_hdr_t *hdr = (const pkt_hdr_t *)buf;
    size_t offset = HDR_LEN;
    
    if (buf_len < HDR_LEN) return -1;
    if (hdr->opt_count > MAX_OPTS) return -1;

    for (uint16_t i = 0; i < hdr->opt_count; i++) {
        if (offset + sizeof(pkt_opt_t) > buf_len) return -1;
        
        const pkt_opt_t *opt = (const pkt_opt_t *)(buf + offset);
        uint16_t opt_len = opt->len;
        
        if (offset + sizeof(pkt_opt_t) + opt_len > buf_len) return -1;
        
        opts_out[i] = 0;
        for (uint16_t j = 0; j < opt_len; j++) {
            opts_out[i] |= ((uint32_t)opt->data[j]) << (8 * j);
        }
        offset += sizeof(pkt_opt_t) + opt_len;
    }
    return 0;
}

int process_packet(const uint8_t *packet, size_t pkt_len) {
    uint32_t opts[MAX_OPTS];
    int ret;
    
    if (pkt_len > MAX_PKT_LEN) return -1;
    
    ret = parse_options(packet, pkt_len, opts);
    if (ret != 0) return ret;
    
    for (int i = 0; i < MAX_OPTS; i++) {
        printf("opt[%d] = 0x%08x\n", i, opts[i]);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    
    uint8_t *buf = malloc(MAX_PKT_LEN);
    if (!buf) { fclose(f); return 1; }
    
    size_t rd = fread(buf, 1, MAX_PKT_LEN, f);
    fclose(f);
    
    int rc = process_packet(buf, rd);
    free(buf);
    return rc;
}

