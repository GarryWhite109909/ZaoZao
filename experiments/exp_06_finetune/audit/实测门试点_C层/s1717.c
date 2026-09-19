#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH_LEN 256

// 将用户数据序列化到指定文件，文件名由用户提供
int serialize_user_data(const char *user_input, const char *filename) {
    char filepath[MAX_PATH_LEN];
    FILE *fp;
    char *data_buffer;

    // 构造文件路径，未对 filename 做任何校验
    snprintf(filepath, sizeof(filepath), "/var/lib/app/data/%s", filename);

    // 模拟从 user_input 提取数据（实际场景可能更复杂）
    data_buffer = (char *)malloc(strlen(user_input) + 1);
    if (!data_buffer) {
        return -1;
    }
    strcpy(data_buffer, user_input);

    // 打开文件写入序列化数据
    fp = fopen(filepath, "w");
    if (!fp) {
        free(data_buffer);
        return -1;
    }

    fputs(data_buffer, fp);
    fclose(fp);
    free(data_buffer);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <data> <filename>\n", argv[0]);
        return 1;
    }

    // 用户可控的 filename 直接传入序列化函数
    return serialize_user_data(argv[1], argv[2]);
}

