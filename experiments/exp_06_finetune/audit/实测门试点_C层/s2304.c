// array_index.c
#include <stdio.h>
#include <stdlib.h>

int get_element(int *arr, int arr_size, int index) {
    if (index < 0) return -1;
    if (index >= arr_size) return -1;
    return arr[index];
}

int main(int argc, char **argv) {
    int data[100] = {0};
    if (argc < 2) return 1;
    int idx = atoi(argv[1]);
    int val = get_element(data, 100, idx);
    printf("value: %d\n", val);
    return 0;
}

