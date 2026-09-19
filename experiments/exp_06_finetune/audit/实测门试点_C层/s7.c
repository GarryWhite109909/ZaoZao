#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64
#define COPY_SIZE(dst, src) (sizeof(dst) < sizeof(src) ? sizeof(dst) : sizeof(src))

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void process_data(Buffer *out, const char *input) {
    char tmp[MAX_BUF];
    /* line 11: 使用宏计算复制长度，但宏基于目标类型大小而非实际容量 */
    size_t copy_len = COPY_SIZE(tmp, input);
    strncpy(tmp, input, copy_len);
    tmp[copy_len - 1] = '\0';

    out->data = (char *)malloc(out->len + 1);
    if (!out->data) return;
    /* line 17: 将 tmp 内容拷贝到堆上，但 out->len 可能小于实际复制长度 */
    memcpy(out->data, tmp, out->len);
    out->data[out->len] = '\0';
}

static void init_buffer(Buffer *b, size_t size) {
    b->data = NULL;
    b->len = size;
}

int main(void) {
    Buffer buf;
    char user_input[128];

    printf("Enter data: ");
    if (fgets(user_input, sizeof(user_input), stdin) == NULL) return 1;
    user_input[strcspn(user_input, "\n")] = '\0';

    init_buffer(&buf, MAX_BUF);
    process_data(&buf, user_input);

    if (buf.data) {
        printf("Processed: %s\n", buf.data);
        free(buf.data);
    }
    return 0;
}

