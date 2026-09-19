#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_BUF 128
typedef struct { char *data; int len; } Buffer;
/* 从样本原样复制 copy_at_offset（含缺陷） */
static int copy_at_offset(Buffer *dst, const char *src, int offset, int src_len) {
    if (offset < 0 || offset > dst->len) { return -1; }
    memcpy(dst->data + offset, src, src_len);
    return 0;
}
int main(void) {
    /* 金丝雀验证：victim 紧随 host 分配，溢出应踩中 victim */
    Buffer host; host.len = 12;
    host.data = calloc(1, 12);
    char *victim = calloc(1, 32);
    memset(victim, 'V', 31);
    const char *payload = "PWNED_PWNED_PWNED_PWNED_PWNED_PWNED";
    int r = copy_at_offset(&host, payload, 0, (int)strlen(payload));
    printf("copy_at_offset 返回 %d\n", r);
    printf("victim 前 8 字节: %.8s (期望 VVVVVVVV)\n", victim);
    printf("host 后堆是否被写穿: %s\n", memcmp(victim, "PWNED_PWNED", 11) == 0 ? "是——越界写实锤" : "否");
    free(host.data); free(victim);
    return 0;
}
