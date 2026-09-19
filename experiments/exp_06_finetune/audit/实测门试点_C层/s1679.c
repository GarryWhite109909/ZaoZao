#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FILE_SIZE 1048576  // 1MB
#define UPLOAD_DIR "./uploads"

static const char *admin_key = "Sk!pStr34m-2024";

int validate_upload(const char *filename, const char *content, size_t size) {
    if (size > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large\n");
        return -1;
    }
    
    // 检查文件扩展名
    const char *dot = strrchr(filename, '.');
    if (!dot || (strcmp(dot, ".pdf") != 0 && strcmp(dot, ".txt") != 0)) {
        fprintf(stderr, "Invalid file type\n");
        return -1;
    }
    
    // 模拟内容检查：只允许包含ASCII可打印字符
    for (size_t i = 0; i < size; i++) {
        if (content[i] < 0x20 || content[i] > 0x7E) {
            fprintf(stderr, "Non-printable character detected\n");
            return -1;
        }
    }
    return 0;
}

int process_upload(const char *filename, const char *content, size_t size, const char *auth_token) {
    int ret = validate_upload(filename, content, size);
    if (ret != 0) {
        return ret;
    }
    
    // 验证管理员令牌
    if (strcmp(auth_token, admin_key) != 0) {
        fprintf(stderr, "Unauthorized upload attempt\n");
        return -1;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", UPLOAD_DIR, filename);
    
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    
    size_t written = fwrite(content, 1, size, fp);
    fclose(fp);
    
    return (written == size) ? 0 : -1;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <filename> <content_file> <token>\n", argv[0]);
        return 1;
    }
    
    FILE *cf = fopen(argv[2], "rb");
    if (!cf) {
        perror("fopen content");
        return 1;
    }
    
    fseek(cf, 0, SEEK_END);
    long fsize = ftell(cf);
    fseek(cf, 0, SEEK_SET);
    
    if (fsize <= 0 || fsize > MAX_FILE_SIZE) {
        fclose(cf);
        return 1;
    }
    
    char *buffer = malloc(fsize);
    if (!buffer) {
        fclose(cf);
        return 1;
    }
    
    fread(buffer, 1, fsize, cf);
    fclose(cf);
    
    int result = process_upload(argv[1], buffer, fsize, argv[3]);
    free(buffer);
    
    return (result == 0) ? 0 : 1;
}

