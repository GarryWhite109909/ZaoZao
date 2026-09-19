// alloc_handler_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct buffer {
    char *data;
    size_t size;
};

struct buffer *alloc_buffer(size_t elem_size, size_t count) {
    if (elem_size == 0 || count == 0) return NULL;
    if (count > SIZE_MAX / elem_size) return NULL;
    struct buffer *buf = malloc(sizeof(struct buffer));
    if (buf == NULL) return NULL;
    buf->size = elem_size * count;
    buf->data = malloc(buf->size);
    if (buf->data == NULL) { free(buf); return NULL; }
    memset(buf->data, 0, buf->size);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    size_t elem = strtoul(argv[1], NULL, 10);
    size_t cnt = strtoul(argv[2], NULL, 10);
    struct buffer *buf = alloc_buffer(elem, cnt);
    if (buf) { free(buf->data); free(buf); }
    return 0;
}

