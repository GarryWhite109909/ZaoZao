// metric_tag_safe.c
#include <stdio.h>
#include <string.h>

void emit_metric(const char *host, const char *metric, int value) {
    char tag[256];
    snprintf(tag, sizeof(tag), "host=%s metric=%s", host, metric);
    printf("%s value=%d\n", tag, value);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <host> <metric> <value>\n");
        return 1;
    }
    emit_metric(argv[1], argv[2], atoi(argv[3]));
    return 0;
}

