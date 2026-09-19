#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    char *data;
    size_t len;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->data = malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) return;
    SAFE_FREE(buf->data);
    free(buf);
}

int process_buffer(Buffer *buf, const char *input) {
    if (!buf || !buf->data || !input) return -1;
    
    size_t input_len = strlen(input);
    if (input_len >= buf->len) {
        return -1;
    }
    
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    return 0;
}

int main(void) {
    Buffer *buf = create_buffer(64);
    if (!buf) return 1;
    
    char input[32];
    printf("Enter string: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        destroy_buffer(buf);
        return 1;
    }
    
    input[strcspn(input, "\n")] = '\0';
    
    if (process_buffer(buf, input) == 0) {
        printf("Processed: %s\n", buf->data);
    }
    
    destroy_buffer(buf);
    return 0;
}

