// file_read_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char *read_file(FILE *fp, size_t offset, size_t len) {
    if (fp == NULL) return NULL;
    if (offset > SIZE_MAX - len) return NULL;
    size_t total = offset + len;
    char *buf = malloc(total + 1);
    if (buf == NULL) return NULL;
    fseek(fp, offset, SEEK_SET);
    size_t rd = fread(buf + offset, 1, len, fp);
    buf[offset + rd] = '\0';
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    FILE *fp = fopen("/tmp/data", "r");
    if (fp) { char *b = read_file(fp, strtoul(argv[1],NULL,10), strtoul(argv[2],NULL,10)); if (b) free(b); fclose(fp); }
    return 0;
}

