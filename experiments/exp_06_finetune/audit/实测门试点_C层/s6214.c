// health_check_safe.c
#include <stdio.h>
#include <string.h>

void report_health(const char *service, int healthy) {
    printf("service: %s\n", service);
    printf("status: %s\n", healthy ? "healthy" : "down");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <service> <healthy>\n");
        return 1;
    }
    report_health(argv[1], atoi(argv[2]));
    return 0;
}

