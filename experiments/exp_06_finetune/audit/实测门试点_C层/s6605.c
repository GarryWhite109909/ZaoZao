// 文件: image_decode.c
#include <stdlib.h>
#include <string.h>

typedef struct { int w, h; unsigned char *px; } Image;

// 解码一行像素到 img->px
int decode_row(Image *img, int row, const unsigned char *src, int src_len) {  // line 8: src/src_len 污染源
    unsigned char *dst = img->px + (row * img->w * 3);  // line 9: 行偏移
    memcpy(dst, src, src_len);  // line 10: 危险 sink，未校验 src_len
    return 0;
}

int main(void) {
    Image img = { .w = 64, .h = 64 };
    img.px = malloc((size_t)img.w * img.h * 3);  // 12288 字节
    unsigned char payload[8192];
    memset(payload, 'A', sizeof(payload));
    decode_row(&img, 0, payload, 8192);  // line 19: 8192 > 192 触发越界写
    free(img.px);
    return 0;
}
