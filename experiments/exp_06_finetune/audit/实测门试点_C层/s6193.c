// log_handler_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *log_fp = NULL;

void init_log(void) {
    log_fp = fopen("/var/log/app.log", "a");
}

void handle_request(const char *query) {
    char buf[1024];
    if (query == NULL) return;
    strncpy(buf, query, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("%s", buf);
    printf("\n");
    if (log_fp) {
        fprintf(log_fp, "%s", buf);
        fputc('\n', log_fp);
        fflush(log_fp);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <query>\n", argv[0]);
        return 1;
    }
    init_log();
    handle_request(argv[1]);
    return 0;
}

