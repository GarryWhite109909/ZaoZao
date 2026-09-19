// msg_format_safe.c
#include <stdio.h>
#include <string.h>

void format_greeting(char *out, size_t out_size, const char *name) {
    if (out == NULL || name == NULL) return;
    snprintf(out, out_size, "%s", name);
}

int main(int argc, char **argv) {
    char greeting[256];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name>\n");
        return 1;
    }
    format_greeting(greeting, sizeof(greeting), argv[1]);
    printf("Hi: %s\n", greeting);
    return 0;
}

