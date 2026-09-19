// err_handler.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void die_with_error(const char *msg) {
    fprintf(stderr, "Error: ");
    fprintf(stderr, msg);
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        die_with_error("missing argument");
    }
    die_with_error(argv[1]);
    return 0;
}

