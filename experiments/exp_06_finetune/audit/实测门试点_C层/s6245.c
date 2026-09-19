// proto_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int parse_header(const char *data, size_t data_len) {
    if (data == NULL || data_len < 4) return -1;
    unsigned field_count = (unsigned char)data[0];
    unsigned payload_len = (unsigned char)data[1];
    size_t needed = 4 + (size_t)field_count * 2 + payload_len;
    if (needed > data_len) return -1;
    if (field_count > 100) return -1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[256] = {0};
    strncpy(buf, argv[1], sizeof(buf) - 1);
    parse_header(buf, strlen(buf));
    return 0;
}

