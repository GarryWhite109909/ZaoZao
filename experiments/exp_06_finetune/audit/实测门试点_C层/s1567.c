#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH_LEN 256
#define MAX_DATA_SIZE 1024

typedef struct {
    char filename[64];
    char data[MAX_DATA_SIZE];
    size_t data_len;
} SerializedData;

int load_serialized_data(const char *filepath, SerializedData *out) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    size_t read_len = fread(out, 1, sizeof(SerializedData), fp);
    fclose(fp);
    if (read_len != sizeof(SerializedData)) return -1;

    // 确保字符串结尾
    out->filename[sizeof(out->filename) - 1] = '\0';
    out->data[out->data_len] = '\0';
    return 0;
}

int process_data(const char *input_file) {
    SerializedData *obj = (SerializedData *)malloc(sizeof(SerializedData));
    if (!obj) return -1;

    if (load_serialized_data(input_file, obj) != 0) {
        free(obj);
        return -1;
    }

    // 根据序列化数据中的文件名进行处理
    char filepath[MAX_PATH_LEN];
    snprintf(filepath, sizeof(filepath), "/var/lib/app/data/%s", obj->filename);

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        free(obj);
        return -1;
    }

    // 处理文件内容
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);
    }

    fclose(fp);
    free(obj);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <serialized_file>\n", argv[0]);
        return 1;
    }
    return process_data(argv[1]);
}

