// error_reporter_safe.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void report_error(const char *user_msg) {
    if (user_msg == NULL) return;
    fprintf(stderr, "Error: ");
    fprintf(stderr, "%s", user_msg);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        report_error("missing argument");
        return 1;
    }
    report_error(argv[1]);
    return 0;
}

