#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 64

typedef struct {
    char *data;
    size_t len;
} Buffer;

int safe_buffer_init(Buffer *buf, size_t size) {
    if (!buf || size == 0 || size > MAX_BUF_SIZE) {
        return -1;
    }
    buf->data = (char *)malloc(size);
    if (!buf->data) {
        return -1;
    }
    buf->len = size;
    memset(buf->data, 0, size);
    return 0;
}

void safe_buffer_clear(Buffer *buf) {
    if (buf) {
        free(buf->data);
        buf->data = NULL;  // 防止悬垂指针
        buf->len = 0;
    }
}

int process_data(Buffer *buf) {
    if (!buf || !buf->data) {
        return -1;
    }
    // 边界检查：确保写入不超过分配大小
    if (buf->len >= MAX_BUF_SIZE) {
        return -1;
    }
    buf->data[buf->len] = 'A';  // 在已分配范围内写入
    return 0;
}

int main(void) {
    Buffer my_buf;
    if (safe_buffer_init(&my_buf, 32) != 0) {
        return 1;
    }
    
    if (process_data(&my_buf) != 0) {
        safe_buffer_clear(&my_buf);
        return 1;
    }
    
    printf("Data: %c\n", my_buf.data[my_buf.len]);
    safe_buffer_clear(&my_buf);
    return 0;
}

