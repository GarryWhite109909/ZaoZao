// logrotate_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_ENTRIES 10000

struct entry { char data[256]; };
static struct entry entries[MAX_ENTRIES];
static size_t entry_count = 0;

int add_entry(const char *data) {
    if (data == NULL) return -1;
    if (entry_count >= MAX_ENTRIES) {
        entry_count = 0;
    }
    strncpy(entries[entry_count].data, data, 255);
    entries[entry_count].data[255] = '\0';
    entry_count++;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    add_entry(argv[1]);
    return 0;
}

