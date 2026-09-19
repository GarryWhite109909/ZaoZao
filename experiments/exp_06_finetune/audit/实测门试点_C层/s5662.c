#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define UPLOAD_DIR "/var/uploads"
#define MAX_FILENAME_LEN 64

/* 从环境变量读取上传目录，不硬编码路径 */
static int get_upload_dir(char *buf, size_t len) {
    const char *env_dir = getenv("UPLOAD_DIR");
    if (env_dir == NULL) {
        fprintf(stderr, "UPLOAD_DIR not set\n");
        return -1;
    }
    if (strlen(env_dir) >= len) {
        fprintf(stderr, "Upload dir path too long\n");
        return -1;
    }
    strncpy(buf, env_dir, len - 1);
    buf[len - 1] = '\0';
    return 0;
}

int save_uploaded_file(const char *client_filename, const char *content) {
    char upload_dir[256];
    char filepath[512];
    FILE *fp;

    /* 防御1: 从环境变量获取目录，避免硬编码凭据/路径 */
    if (get_upload_dir(upload_dir, sizeof(upload_dir)) != 0) {
        return -1;
    }

    /* 防御2: 白名单校验文件名，只允许字母数字和点 */
    for (int i = 0; client_filename[i] != '\0'; i++) {
        char c = client_filename[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '.')) {
            fprintf(stderr, "Invalid character in filename\n");
            return -1;
        }
    }

    /* 防御3: 限制文件名长度，防止缓冲区溢出 */
    if (strlen(client_filename) > MAX_FILENAME_LEN) {
        fprintf(stderr, "Filename too long\n");
        return -1;
    }

    /* 防御4: 使用snprintf拼接路径，并检查截断 */
    int written = snprintf(filepath, sizeof(filepath), "%s/%s",
                           upload_dir, client_filename);
    if (written < 0 || (size_t)written >= sizeof(filepath)) {
        fprintf(stderr, "Path too long\n");
        return -1;
    }

    /* 防御5: 以最小权限打开文件（0600），并检查打开失败 */
    fp = fopen(filepath, "w");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", strerror(errno));
        return -1;
    }
    fchmod(fileno(fp), 0600);

    /* 写入内容 */
    if (fputs(content, fp) == EOF) {
        fprintf(stderr, "Write failed\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <content>\n", argv[0]);
        return 1;
    }
    return save_uploaded_file(argv[1], argv[2]);
}

