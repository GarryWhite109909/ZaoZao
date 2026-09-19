// deploy_log_safe.c
#include <stdio.h>
#include <string.h>

void log_deploy(const char *version, const char *env) {
    FILE *fp = fopen("/var/log/deploy.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "version=%s env=%s deployed\n", version, env);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <version> <env>\n");
        return 1;
    }
    log_deploy(argv[1], argv[2]);
    return 0;
}

