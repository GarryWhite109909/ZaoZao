// custom_log_safe.c
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

void logf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <msg>\n");
        return 1;
    }
    logf("%s", argv[1]);
    return 0;
}

