#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
    int refcount;
} buffer_t;

static buffer_t *buffer_create(const char *src) {
    buffer_t *buf = (buffer_t *)malloc(sizeof(buffer_t));
    if (!buf) return NULL;
    buf->len = strlen(src);
    buf->data = (char *)malloc(buf->len + 1);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    strcpy(buf->data, src);
    buf->refcount = 1;
    return buf;
}

static void buffer_release(buffer_t *buf) {
    if (buf && --buf->refcount == 0) {
        free(buf->data);
        free(buf);
    }
}

static char *buffer_get(buffer_t *buf) {
    return buf->data;
}

/* 模拟跨模块回调：外部函数借用 buffer 后不归还引用 */
static void process_external(buffer_t *buf) {
    char *tmp = buffer_get(buf);
    printf("processing: %s\n", tmp);
    /* 外部模块错误地释放了资源，但 refcount 未管理 */
    free(tmp);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    buffer_t *buf = buffer_create(argv[1]);
    if (!buf) return 1;

    process_external(buf);           /* 第 38 行：跨函数借用，外部释放 data */

    buffer_release(buf);             /* 第 40 行：再次释放 → UAF / Double Free */
    printf("done\n");
    return 0;
}

