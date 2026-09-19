// signed_cmp_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_size(size_t user_size) {
    char buf[256];
    if (user_size > sizeof(buf)) return -1;
    memset(buf, 0, user_size);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *endp;
    unsigned long sz = strtoul(argv[1], &endp, 10);
    if (*endp != '\0') return 1;
    return check_size(sz);
}

