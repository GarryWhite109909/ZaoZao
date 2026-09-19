// task_log_safe.c
#include <stdio.h>
#include <string.h>

void log_task(const char *user, const char *task, int result) {
    FILE *fp = fopen("/var/log/tasks.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "user=%s task=%s result=%d\n", user, task, result);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <user> <task> <result>\n");
        return 1;
    }
    log_task(argv[1], argv[2], atoi(argv[3]));
    return 0;
}

