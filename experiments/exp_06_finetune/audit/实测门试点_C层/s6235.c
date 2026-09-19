// packet_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int parse_packet(const char *data, size_t data_len, size_t header_len, size_t body_len) {
    if (data == NULL) return -1;
    if (header_len > data_len) return -1;
    if (body_len > data_len - header_len) return -1;
    char buf[4096];
    size_t total = header_len + body_len;
    if (total > sizeof(buf)) return -1;
    memcpy(buf, data, total);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) return 1;
    char data[1024] = {0};
    parse_packet(data, sizeof(data), strtoul(argv[1],NULL,10), strtoul(argv[2],NULL,10));
    return 0;
}

