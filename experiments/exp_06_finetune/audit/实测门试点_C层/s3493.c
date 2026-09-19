#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

void safe_free_buffer(Buffer *buf) {
    if (buf == NULL) return;
    free(buf->data);
    buf->data = NULL;  // line 11: 释放后立即置空，阻断悬垂指针
    buf->len = 0;
}

int process_buffer(Buffer *buf) {
    if (buf == NULL || buf->data == NULL) {
        return -1;  // line 16: 空指针检查，防御二次释放或空解引用
    }
    // 模拟处理数据
    size_t total = 0;
    for (size_t i = 0; i < buf->len; i++) {
        total += buf->data[i];
    }
    return (int)total;
}

int main(void) {
    Buffer buf;
    buf.data = (char *)malloc(1024);
    if (buf.data == NULL) {
        return 1;  // 分配失败处理
    }
    buf.len = 1024;
    memset(buf.data, 0x41, buf.len);

    // 第一次使用
    int result1 = process_buffer(&buf);
    printf("First result: %d\n", result1);

    // 释放并置空
    safe_free_buffer(&buf);  // line 36: 调用安全释放函数

    // 第二次使用前检查
    if (buf.data == NULL) {
        printf("Buffer already freed, skipping\n");  // line 40: 检测到NULL，跳过使用
        return 0;
    }

    // 此路径不可达，但为完整性保留
    int result2 = process_buffer(&buf);
    printf("Second result: %d\n", result2);
    return 0;
}

