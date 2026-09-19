#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void destroy_buffer(Buffer *buf) {
    if (!buf) return;
    free(buf->data);
    buf->data = NULL;  // 关键防御：释放后置NULL
    free(buf);
}

int process_buffer(Buffer *buf, const char *input) {
    if (!buf || !buf->data) return -1;  // 防御：检查data是否为NULL
    if (strlen(input) >= buf->len) return -1;  // 防御：边界检查
    strcpy(buf->data, input);
    return 0;
}

int main() {
    Buffer *buf = create_buffer(64);
    if (!buf) return 1;
    
    if (process_buffer(buf, "hello") == 0) {
        printf("Processed: %s\n", buf->data);
    }
    
    destroy_buffer(buf);
    // 此处buf已释放且data为NULL，但buf指针本身悬垂
    // 后续若误用buf->data，因data为NULL，process_buffer会返回-1
    // 但直接访问buf->data仍为UB，不过本代码未再使用buf
    
    return 0;
}

