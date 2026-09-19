// auth_log_safe.c
#include <stdio.h>
#include <string.h>
#include <time.h>

void log_auth(FILE *fp, const char *user, const char *status) {
    if (fp == NULL || user == NULL || status == NULL) return;
    time_t now = time(NULL);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(fp, "[%s] auth user=%s status=%s\n", tbuf, user, status);
    fflush(fp);
}

int main(int argc, char **argv) {
    FILE *fp = fopen("/var/log/auth.log", "a");
    if (!fp) return 1;
    log_auth(fp, argc > 1 ? argv[1] : "anon", "success");
    fclose(fp);
    return 0;
}

