// url_builder_safe.c
#include <stdio.h>
#include <string.h>

void build_url(char *out, size_t out_size, const char *path) {
    if (out == NULL || path == NULL) return;
    snprintf(out, out_size, "%s", path);
}

int main(int argc, char **argv) {
    char url[512];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n");
        return 1;
    }
    build_url(url, sizeof(url), argv[1]);
    printf("URL: %s\n", url);
    return 0;
}

