// block_calc.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 4096

char *alloc_blocks(size_t count) {
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

