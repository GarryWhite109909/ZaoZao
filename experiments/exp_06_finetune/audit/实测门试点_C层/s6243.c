// config_parse_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int parse_array(const char *spec, size_t spec_len, int *out, size_t out_cap) {
    if (spec == NULL || out == NULL) return -1;
    size_t count = 0;
    size_t i = 0;
    while (i < spec_len && count < out_cap) {
        if (spec[i] == ',') { count++; }
        i++;
    }
    count++;
    if (count > out_cap) return -1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int out[100];
    parse_array(argv[1], strlen(argv[1]), out, 100);
    return 0;
}

