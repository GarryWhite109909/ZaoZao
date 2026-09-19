#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF_SIZE 64

typedef struct {
    char *data;
    size_t len;
} Buffer;

static int process_packet(const char *input, size_t input_len) {
    Buffer buf;
    buf.data = (char *)malloc(MAX_BUF_SIZE);
    if (!buf.data) {
        return -1;
    }
    buf.len = 0;

    if (input_len > MAX_BUF_SIZE - 1) {
        free(buf.data);
        return -2;
    }

    memcpy(buf.data, input, input_len);
    buf.data[input_len] = '\0';
    buf.len = input_len;

    if (buf.len > 0 && buf.data[0] == 'E') {
        printf("Emergency packet received\n");
    }

    free(buf.data);
    buf.data = NULL;
    return 0;
}

int main(void) {
    const char *test_input = "Hello";
    int ret = process_packet(test_input, strlen(test_input));
    if (ret != 0) {
        fprintf(stderr, "Error: %d\n", ret);
    }
    return 0;
}

