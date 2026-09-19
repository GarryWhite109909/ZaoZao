#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_PATH 256
#define DATA_DIR "/var/lib/app/data/"

typedef struct {
    char filename[64];
    char content[512];
} DataPacket;

int serialize_data(const char *user_input) {
    DataPacket packet;
    char filepath[MAX_PATH];
    int fd;

    // 解析用户输入，格式: "filename:content"
    const char *colon = strchr(user_input, ':');
    if (colon == NULL) {
        fprintf(stderr, "Invalid format\n");
        return -1;
    }

    size_t name_len = colon - user_input;
    if (name_len >= sizeof(packet.filename)) {
        fprintf(stderr, "Filename too long\n");
        return -1;
    }

    // 提取文件名
    strncpy(packet.filename, user_input, name_len);
    packet.filename[name_len] = '\0';

    // 提取内容
    strncpy(packet.content, colon + 1, sizeof(packet.content) - 1);
    packet.content[sizeof(packet.content) - 1] = '\0';

    // 构造完整路径
    snprintf(filepath, sizeof(filepath), "%s%s", DATA_DIR, packet.filename);

    // 写入序列化数据
    fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    write(fd, packet.content, strlen(packet.content));
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename:content>\n", argv[0]);
        return 1;
    }
    return serialize_data(argv[1]);
}

