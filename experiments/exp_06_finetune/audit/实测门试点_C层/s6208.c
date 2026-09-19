// rate_limit_log_safe.c
#include <stdio.h>
#include <string.h>

void log_rate_limit(const char *ip, int count, int limit) {
    FILE *fp = fopen("/var/log/ratelimit.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "ip=%s count=%d limit=%d\n", ip, count, limit);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ip> <count> <limit>\n");
        return 1;
    }
    log_rate_limit(argv[1], atoi(argv[2]), atoi(argv[3]));
    return 0;
}

