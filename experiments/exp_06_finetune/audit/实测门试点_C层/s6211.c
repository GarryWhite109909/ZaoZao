// file_scan_log_safe.c
#include <stdio.h>
#include <string.h>

void log_scan(FILE *fp, const char *path, const char *status) {
    if (fp == NULL || path == NULL || status == NULL) return;
    fprintf(fp, "scan: %s -> %s\n", path, status);
    fflush(fp);
}

int main(int argc, char **argv) {
    FILE *fp = fopen("/var/log/scan.log", "a");
    if (!fp) return 1;
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path> <status>\n");
        return 1;
    }
    log_scan(fp, argv[1], argv[2]);
    fclose(fp);
    return 0;
}

