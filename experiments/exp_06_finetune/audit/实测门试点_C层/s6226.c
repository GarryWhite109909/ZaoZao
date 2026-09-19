// copy_handler_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int copy_data(char *dst, size_t dst_cap, size_t offset, const char *src, size_t len) {
    if (dst == NULL || src == NULL) return -1;
    if (offset > dst_cap) return -1;
    if (len > dst_cap - offset) return -1;
    memcpy(dst + offset, src, len);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    size_t offset = strtoul(argv[1], NULL, 10);
    size_t len = strtoul(argv[2], NULL, 10);
    char buf[1024];
    copy_data(buf, sizeof(buf), offset, "data", len);
    return 0;
}

