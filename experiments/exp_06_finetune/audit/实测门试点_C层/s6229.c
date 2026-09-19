// length_calc_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char *concat(const char *a, const char *b) {
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    if (len_a > SIZE_MAX - len_b - 1) return NULL;
    size_t total = len_a + len_b + 1;
    char *result = malloc(total);
    if (result == NULL) return NULL;
    memcpy(result, a, len_a);
    memcpy(result + len_a, b, len_b);
    result[total - 1] = '\0';
    return result;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    char *r = concat(argv[1], argv[2]);
    if (r) { printf("%s\n", r); free(r); }
    return 0;
}

