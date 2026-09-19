// paginate_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define PAGE_SIZE 20

int get_page_range(size_t total, size_t page, size_t *start, size_t *end) {
    if (total == 0 || start == NULL || end == NULL) return -1;
    if (page == 0) return -1;
    if (page > (total + PAGE_SIZE - 1) / PAGE_SIZE) return -1;
    *start = (page - 1) * PAGE_SIZE;
    *end = *start + PAGE_SIZE;
    if (*end > total) *end = total;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    size_t total = strtoul(argv[1], NULL, 10);
    size_t page = strtoul(argv[2], NULL, 10);
    size_t s, e;
    get_page_range(total, page, &s, &e);
    return 0;
}

