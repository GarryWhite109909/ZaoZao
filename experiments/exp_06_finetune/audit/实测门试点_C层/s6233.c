// image_alloc_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char *alloc_image_buffer(size_t width, size_t height, size_t channels) {
    if (width == 0 || height == 0 || channels == 0) return NULL;
    if (width > SIZE_MAX / height) return NULL;
    size_t pixels = width * height;
    if (pixels > SIZE_MAX / channels) return NULL;
    size_t total = pixels * channels;
    char *buf = malloc(total);
    if (buf) memset(buf, 0, total);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 4) return 1;
    size_t w = strtoul(argv[1], NULL, 10);
    size_t h = strtoul(argv[2], NULL, 10);
    size_t c = strtoul(argv[3], NULL, 10);
    char *buf = alloc_image_buffer(w, h, c);
    if (buf) free(buf);
    return 0;
}

