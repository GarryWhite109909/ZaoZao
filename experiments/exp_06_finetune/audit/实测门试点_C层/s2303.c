// signed_cmp.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_size(int user_size) {
    if (user_size < 0) return -1;
    char buf[256];
    if (user_size > sizeof(buf)) return -1;
    memset(buf, 0, user_size);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int sz = atoi(argv[1]);
    return check_size(sz);
}

