// audit_log_safe.c
#include <stdio.h>
#include <string.h>

void audit_log(const char *action, const char *resource) {
    FILE *fp = fopen("/var/log/audit.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "action=%s resource=%s\n", action, resource);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <action> <resource>\n");
        return 1;
    }
    audit_log(argv[1], argv[2]);
    return 0;
}

