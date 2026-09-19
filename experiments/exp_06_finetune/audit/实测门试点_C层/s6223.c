// ws_log_safe.c
#include <stdio.h>
#include <string.h>

void log_ws_msg(const char *session, const char *msg) {
    FILE *fp = fopen("/var/log/ws.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "session=%s msg=%s\n", session, msg);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <session> <msg>\n");
        return 1;
    }
    log_ws_msg(argv[1], argv[2]);
    return 0;
}

