#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64

typedef struct {
    char *data;
    size_t size;
} Buffer;

Buffer *create_buffer(size_t size) {
    if (size == 0 || size > MAX_BUF) {
        return NULL;
    }
    
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) {
        return NULL;
    }
    
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    buf->size = size;
    memset(buf->data, 0, size);
    return buf;
}

void destroy_buffer(Buffer *buf) {
    if (!buf) {
        return;
    }
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    free(buf);
}

int main(void) {
    Buffer *buf = create_buffer(32);
    if (!buf) {
        return 1;
    }
    
    const char *msg = "safe buffer";
    size_t msg_len = strlen(msg);
    
    if (msg_len < buf->size) {
        memcpy(buf->data, msg, msg_len + 1);
    }
    
    printf("Content: %s\n", buf->data);
    destroy_buffer(buf);
    return 0;
}

