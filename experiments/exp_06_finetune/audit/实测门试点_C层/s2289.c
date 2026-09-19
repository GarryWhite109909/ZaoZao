// sys_logger.c
#include <syslog.h>
#include <stdio.h>
#include <string.h>

void log_message(int priority, const char *msg) {
    if (msg == NULL) return;
    openlog("app", LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(priority, msg);
    closelog();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <msg>\n");
        return 1;
    }
    log_message(LOG_INFO, argv[1]);
    return 0;
}

