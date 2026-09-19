#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF_SIZE 64

typedef struct {
    char data[MAX_BUF_SIZE];
    int length;
} Buffer;

void process_input(Buffer *buf, const char *input) {
    size_t input_len = strlen(input);
    
    if (input_len >= MAX_BUF_SIZE) {
        printf("Input too long\n");
        return;
    }
    
    strcpy(buf->data, input);
    buf->length = (int)input_len;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    Buffer *buf = (Buffer*)malloc(sizeof(Buffer));
    if (!buf) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    process_input(buf, argv[1]);
    printf("Processed: %s (len=%d)\n", buf->data, buf->length);
    
    free(buf);
    return 0;
}

