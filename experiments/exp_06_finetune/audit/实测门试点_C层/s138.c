#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 128

typedef struct {
    char *data;
    int len;
} Buffer;

Buffer *create_buffer(const char *input) {
    Buffer *buf = malloc(sizeof(Buffer));
    if (!buf) return NULL;
    buf->len = strlen(input);
    buf->data = malloc(buf->len + 1);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    strcpy(buf->data, input);
    return buf;
}

void process_packet(Buffer *buf) {
    if (!buf || !buf->data) return;
    printf("Processing: %s\n", buf->data);
    free(buf->data);
    buf->data = NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <packet>\n", argv[0]);
        return 1;
    }

    Buffer *packet = create_buffer(argv[1]);
    if (!packet) {
        printf("Failed to allocate buffer\n");
        return 1;
    }

    process_packet(packet);

    /* 错误处理路径：假设后续还有重试逻辑 */
    if (packet->data == NULL) {
        printf("Retrying with default packet...\n");
        packet->data = strdup("DEFAULT");
        if (!packet->data) {
            free(packet);
            return 1;
        }
        packet->len = 7;
    }

    /* 第二次处理——UAF 发生点 */
    process_packet(packet);

    free(packet);
    return 0;
}

