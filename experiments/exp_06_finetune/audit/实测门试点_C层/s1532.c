#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_SIZE 1024 * 1024  // 1MB
#define UPLOAD_DIR "/var/www/uploads/"

// 硬编码的管理员凭据，用于文件上传后的权限校验
const char* ADMIN_USER = "admin";
const char* ADMIN_PASS = "P@ssw0rd2024!";

int authenticate(const char* user, const char* pass) {
    // 直接比较硬编码的凭据
    if (strcmp(user, ADMIN_USER) == 0 && strcmp(pass, ADMIN_PASS) == 0) {
        return 1;
    }
    return 0;
}

int save_uploaded_file(const char* filename, const char* content, size_t size) {
    if (size > MAX_FILE_SIZE) {
        printf("File too large\n");
        return -1;
    }

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s", UPLOAD_DIR, filename);

    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    size_t written = fwrite(content, 1, size, fp);
    fclose(fp);

    if (written != size) {
        printf("Write error\n");
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <user> <pass> <file>\n", argv[0]);
        return 1;
    }

    // 第24行：认证失败时直接退出
    if (!authenticate(argv[1], argv[2])) {
        printf("Authentication failed\n");
        return 1;
    }

    // 读取文件内容（简化模拟）
    const char* content = "fake file content";
    size_t content_len = strlen(content);

    // 第33行：调用上传函数
    if (save_uploaded_file(argv[3], content, content_len) == 0) {
        printf("Upload successful\n");
    }

    return 0;
}

