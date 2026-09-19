#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_INPUT 128

typedef struct {
    char data[64];
    int length;
} Buffer;

void process_input(Buffer *buf, const char *input) {
    int input_len = strlen(input);
    
    // Copy input into buffer
    strcpy(buf->data, input);
    buf->length = input_len;
    
    // Simulate some processing
    if (buf->length > 10) {
        printf("Processing long input: %s\n", buf->data);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) {
        return 1;
    }
    
    process_input(buf, argv[1]);
    
    printf("Buffer content: %s\n", buf->data);
    
    free(buf);
    return 0;
}

