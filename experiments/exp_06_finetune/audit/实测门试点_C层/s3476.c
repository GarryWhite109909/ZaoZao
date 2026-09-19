#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

// 安全的内存管理：free后置NULL，防止悬垂指针复用
void safe_free(Buffer *buf) {
    if (buf == NULL) return;
    free(buf->data);
    buf->data = NULL;  // 关键防御：置NULL阻断UAF路径
    buf->len = 0;
}

// 复制缓冲区，带边界检查
int copy_buffer(Buffer *dst, const Buffer *src) {
    if (dst == NULL || src == NULL) return -1;
    if (src->len == 0) {
        dst->data = NULL;
        dst->len = 0;
        return 0;
    }
    
    char *new_data = (char *)malloc(src->len);
    if (new_data == NULL) return -1;
    
    memcpy(new_data, src->data, src->len);  // 长度来自src->len，信任已校验的元数据
    safe_free(dst);  // 先释放旧数据，置NULL
    
    dst->data = new_data;
    dst->len = src->len;
    return 0;
}

int main() {
    Buffer buf1 = {NULL, 0};
    Buffer buf2 = {NULL, 0};
    
    // 初始化buf1
    buf1.data = (char *)malloc(10);
    if (buf1.data == NULL) return 1;
    memcpy(buf1.data, "hello", 6);
    buf1.len = 6;
    
    // 复制并验证
    if (copy_buffer(&buf2, &buf1) != 0) {
        safe_free(&buf1);
        return 1;
    }
    
    printf("buf2: %.*s\n", (int)buf2.len, buf2.data);
    
    // 清理
    safe_free(&buf1);
    safe_free(&buf2);
    return 0;
}

