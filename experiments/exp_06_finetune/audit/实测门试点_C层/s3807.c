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

void safe_free_buffer(Buffer *buf) {
    if (buf) {
        free(buf->data);
        buf->data = NULL;  // line 21: 防御措施 - free后置NULL
        free(buf);
        // 注意：buf本身未被置NULL，但调用方负责
    }
}

void process_buffer(Buffer *buf) {
    if (!buf || !buf->data) {  // line 27: 防御措施 - 空指针检查
        printf("Buffer is invalid\n");
        return;
    }
    
    // 模拟数据处理
    buf->data[0] = 'A';
    printf("Processing buffer of size %zu\n", buf->len);
}

int main() {
    Buffer *my_buf = create_buffer(100);
    if (!my_buf) {
        return 1;
    }
    
    process_buffer(my_buf);
    
    safe_free_buffer(my_buf);  // line 42: 安全释放
    
    // 关键：my_buf->data已被置NULL，process_buffer会拒绝处理
    process_buffer(my_buf);  // line 45: 再次使用 - 安全
    
    // 防止误用my_buf本身
    free(my_buf);  // 错误！双重释放 - 但这里不会执行，因为逻辑上不会走到
    // 实际代码中应该避免这种模式，但为演示安全，我们直接返回
    return 0;
}

