#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 256

typedef struct {
    char *data;
    size_t len;
} Buffer;

int process_data(const char *input, size_t input_len) {
    if (input == NULL || input_len == 0 || input_len > MAX_BUF_SIZE) {
        return -1;
    }

    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (buf == NULL) {
        return -1;
    }

    buf->data = (char *)malloc(input_len + 1);
    if (buf->data == NULL) {
        free(buf);
        buf = NULL;
        return -1;
    }

    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = input_len;

    printf("Processed: %s\n", buf->data);

    free(buf->data);
    buf->data = NULL;
    free(buf);
    buf = NULL;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    size_t input_len = strlen(argv[1]);
    if (input_len > MAX_BUF_SIZE) {
        fprintf(stderr, "Input too long\n");
        return 1;
    }

    return process_data(argv[1], input_len);
}

