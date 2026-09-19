// gateway_log_safe.c
#include <stdio.h>
#include <string.h>

void log_request(const char *method, const char *path, int status) {
    FILE *fp = fopen("/var/log/gateway.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "method=%s path=%s status=%d\n", method, path, status);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <method> <path> <status>\n");
        return 1;
    }
    log_request(argv[1], argv[2], atoi(argv[3]));
    return 0;
}

