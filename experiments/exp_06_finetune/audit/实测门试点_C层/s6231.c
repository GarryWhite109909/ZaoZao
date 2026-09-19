// block_calc_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 4096

char *alloc_blocks(size_t count) {
    if (count > SIZE_MAX / BLOCK_SIZE) return NULL;
    size_t total = count * BLOCK_SIZE;
    char *buf = malloc(total);
    if (buf == NULL) return NULL;
    memset(buf, 0, total);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t count = strtoul(argv[1], NULL, 10);
    char *buf = alloc_blocks(count);
    if (buf) free(buf);
    return 0;
}

