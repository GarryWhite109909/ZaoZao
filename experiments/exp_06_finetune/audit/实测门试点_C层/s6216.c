// migrate_log_safe.c
#include <stdio.h>
#include <string.h>

void log_migration(const char *table, int rows) {
    FILE *fp = fopen("/var/log/migrate.log", "a");
    if (fp == NULL) return;
    fprintf(fp, "table=%s rows=%d migrated\n", table, rows);
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <table> <rows>\n");
        return 1;
    }
    log_migration(argv[1], atoi(argv[2]));
    return 0;
}

