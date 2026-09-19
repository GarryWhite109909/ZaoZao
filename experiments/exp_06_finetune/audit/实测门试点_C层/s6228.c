// array_index_safe.c
#include <stdio.h>
#include <stdlib.h>

int get_element(const int *arr, size_t arr_size, size_t index) {
    if (index >= arr_size) return -1;
    return arr[index];
}

int main(int argc, char **argv) {
    int data[100] = {0};
    if (argc < 2) return 1;
    char *endp;
    unsigned long idx = strtoul(argv[1], &endp, 10);
    if (*endp != '\0' || idx > 99) {
        fprintf(stderr, "invalid index\n");
        return 1;
    }
    int val = get_element(data, 100, idx);
    printf("value: %d\n", val);
    return 0;
}

