#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 1024

typedef struct {
    char *data;
    size_t len;
} Buffer;

static Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (buf == NULL) {
        return NULL;
    }
    
    buf->data = (char *)malloc(size);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }
    
    buf->len = size;
    return buf;
}

static void destroy_buffer(Buffer *buf) {
    if (buf == NULL) {
        return;
    }
    
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;  // 防止悬垂指针
    }
    
    free(buf);
}

int main(void) {
    Buffer *buf = create_buffer(MAX_BUF_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }
    
    const char *message = "Hello, secure memory management!";
    size_t msg_len = strlen(message);
    
    // 边界检查：确保消息长度不超过缓冲区容量
    if (msg_len >= buf->len) {
        fprintf(stderr, "Message too long\n");
        destroy_buffer(buf);
        return 1;
    }
    
    memcpy(buf->data, message, msg_len);
    buf->data[msg_len] = '\0';
    
    printf("Buffer content: %s\n", buf->data);
    
    destroy_buffer(buf);
    buf = NULL;  // 防止后续误用
    
    return 0;
}

