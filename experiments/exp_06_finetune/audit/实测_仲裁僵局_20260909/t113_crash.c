#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char *data; int len; } Buffer;
static int copy_at_offset(Buffer *dst, const char *src, int offset, int src_len) {
    if (offset < 0 || offset > dst->len) { return -1; }
    memcpy(dst->data + offset, src, src_len);
    return 0;
}
int main(void) {
    Buffer host; host.len = 12;
    host.data = calloc(1, 12);
    char *big = malloc(1 << 20);
    memset(big, 'A', 1 << 20);
    printf("发起 1MB 越界写（12 字节缓冲）...\n"); fflush(stdout);
    copy_at_offset(&host, big, 0, 1 << 20);
    printf("幸存——memcpy 未崩（罕见）\n");
    return 0;
}
