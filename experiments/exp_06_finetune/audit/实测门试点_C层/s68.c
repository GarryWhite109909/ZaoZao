#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

void process_input(Buffer *buf, const char *input) {
    if (!buf || !input) return;
    // Vulnerability: potential buffer overflow if input exceeds buf->len
    strcpy(buf->data, input);  // line 24: unsafe copy
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    Buffer *buf = create_buffer(MAX_BUF);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    
    process_input(buf, argv[1]);  // line 35: user input flows to vulnerable function
    
    printf("Processed: %s\n", buf->data);
    
    free(buf->data);  // line 39
    free(buf);        // line 40
    return 0;
}

