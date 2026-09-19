#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MAX_BUF_SIZE 1024

typedef struct {
    char *data;
    size_t len;
    int is_encrypted;
} Buffer;

Buffer *create_buffer(size_t size) {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return NULL;
    
    buf->data = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf->data == MAP_FAILED) {
        free(buf);
        return NULL;
    }
    buf->len = size;
    buf->is_encrypted = 0;
    return buf;
}

void cleanup_buffer(Buffer *buf) {
    if (!buf) return;
    if (buf->data) {
        munmap(buf->data, buf->len);
        buf->data = NULL;
    }
    free(buf);
}

int main() {
    Buffer *buf = create_buffer(512);
    if (!buf) return -1;
    
    const char *secret = "MySuperSecretKey123";  // 漏洞行：硬编码密钥
    strncpy(buf->data, secret, strlen(secret));
    buf->is_encrypted = 1;
    
    // 模拟使用缓冲区
    printf("Buffer data: %s\n", buf->data);
    
    cleanup_buffer(buf);
    return 0;
}

