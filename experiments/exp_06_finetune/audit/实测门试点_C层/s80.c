#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH 256

typedef struct {
    char *data;
    size_t len;
} Buffer;

int process_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    Buffer buf;
    buf.data = (char *)malloc(MAX_PATH);
    if (!buf.data) {
        fclose(fp);
        return -1;
    }
    buf.len = MAX_PATH;

    size_t n = fread(buf.data, 1, buf.len - 1, fp);
    buf.data[n] = '\0';
    fclose(fp);

    char *tmp = (char *)malloc(MAX_PATH);
    if (!tmp) {
        free(buf.data);
        return -1;
    }

    // 模拟对数据的处理
    snprintf(tmp, MAX_PATH, "processed:%s", buf.data);

    // 释放 buf.data，但没有置 NULL
    free(buf.data);

    // 错误路径：如果后续操作失败，会重复释放
    if (n > 100) {
        // 模拟某些条件
        free(tmp);
        free(buf.data);  // 双重释放
        return -2;
    }

    free(tmp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    return process_file(argv[1]);
}

