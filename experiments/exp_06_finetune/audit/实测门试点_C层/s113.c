#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 128

typedef struct {
    char *data;
    int len;
} Buffer;

/* 内部辅助函数：按指定偏移拷贝，返回是否成功 */
static int copy_at_offset(Buffer *dst, const char *src, int offset, int src_len) {
    if (offset < 0 || offset > dst->len) {
        return -1;
    }
    /* 缺少剩余空间检查：offset+src_len可能超过dst->len */
    memcpy(dst->data + offset, src, src_len);
    return 0;
}

/* 外部接口：合并两个缓冲区 */
int merge_buffers(Buffer *dst, const Buffer *src1, const Buffer *src2) {
    if (!dst || !src1 || !src2) {
        return -1;
    }
    int total = src1->len + src2->len;
    if (total > MAX_BUF) {
        return -1;
    }

    char *tmp = (char *)malloc(total);
    if (!tmp) {
        return -1;
    }
    memcpy(tmp, src1->data, src1->len);
    memcpy(tmp + src1->len, src2->data, src2->len);

    /* 先拷贝到临时缓冲区，安全 */
    copy_at_offset(dst, tmp, 0, total);

    free(tmp);
    return 0;
}

int main() {
    Buffer a = {NULL, 0}, b = {NULL, 0}, out = {NULL, 0};
    char buf1[64] = "hello";
    char buf2[64] = " world!";

    a.data = buf1; a.len = strlen(buf1);
    b.data = buf2; b.len = strlen(buf2);

    out.data = (char *)malloc(MAX_BUF);
    out.len = MAX_BUF;

    if (merge_buffers(&out, &a, &b) == 0) {
        printf("merged: %s\n", out.data);
    }

    free(out.data);
    return 0;
}

