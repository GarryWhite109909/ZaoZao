#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
} Buffer;

/* SAFE: 所有释放操作都通过 destroy_buffer 完成，且释放后立即置 NULL */
static void destroy_buffer(Buffer *buf) {
    if (buf == NULL) return;
    free(buf->data);
    buf->data = NULL;  // line 12: 防止悬垂指针
    buf->len = 0;
}

/* SAFE: 拷贝函数内部不持有指针，只做值传递 */
static Buffer copy_buffer(const Buffer *src) {
    Buffer out = {0};
    if (src == NULL || src->data == NULL) return out;
    out.data = (char *)malloc(src->len + 1);
    if (out.data == NULL) return out;
    memcpy(out.data, src->data, src->len);
    out.data[src->len] = '\0';
    out.len = src->len;
    return out;
}

/* SAFE: 使用后立即销毁，且调用方不再引用 */
static void process_buffer(Buffer *buf) {
    if (buf == NULL || buf->data == NULL) return;
    printf("len=%zu, data=%s\n", buf->len, buf->data);
    destroy_buffer(buf);  // line 29: 释放后 buf->data 被置 NULL
}

int main(void) {
    Buffer original = {0};
    original.data = (char *)malloc(16);
    if (original.data == NULL) return 1;
    strcpy(original.data, "hello");
    original.len = strlen(original.data);

    Buffer copy = copy_buffer(&original);
    if (copy.data == NULL) {
        destroy_buffer(&original);
        return 1;
    }

    process_buffer(&original);  // line 43: original.data 在函数内被置 NULL

    /* SAFE: 此处 original.data 已为 NULL，不会二次释放 */
    destroy_buffer(&original);  // line 46: free(NULL) 是安全的

    /* copy 是独立副本，安全使用 */
    printf("copy: %s\n", copy.data);
    destroy_buffer(&copy);  // line 50: 最终释放

    return 0;
}

