// buf_printer.c
#include <stdio.h>
#include <string.h>

void print_buf(char *out, size_t out_size, const char *user_data) {
    if (out == NULL || user_data == NULL) return;
    sprintf(out, user_data);
    printf("output: %s\n", out);
}

int main(int argc, char **argv) {
    char buffer[256];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <data>\n");
        return 1;
    }
    print_buf(buffer, sizeof(buffer), argv[1]);
    return 0;
}

