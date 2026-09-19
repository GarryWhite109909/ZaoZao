// grpc_log_safe.c
#include <stdio.h>
#include <string.h>

void log_grpc(const char *method, const char *peer, int code) {
    FILE *fp = fopen("/var/log/grpc.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "method=%s peer=%s code=%d\n", method, peer, code);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <method> <peer> <code>\n");
        return 1;
    }
    log_grpc(argv[1], argv[2], atoi(argv[3]));
    return 0;
}

