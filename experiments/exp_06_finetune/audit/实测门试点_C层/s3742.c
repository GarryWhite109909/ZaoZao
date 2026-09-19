#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FILENAME 256
#define UPLOAD_DIR "/var/uploads"

int validate_extension(const char *filename) {
    const char *allowed[] = {".txt", ".jpg", ".png"};
    size_t len = strlen(filename);
    for (int i = 0; i < 3; i++) {
        size_t ext_len = strlen(allowed[i]);
        if (len >= ext_len && strcmp(filename + len - ext_len, allowed[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void process_upload(const char *client_filename) {
    char safe_path[512];
    char *secret = getenv("UPLOAD_SECRET");  // 环境变量而非硬编码
    
    if (!secret || strlen(secret) < 16) {
        fprintf(stderr, "Server misconfigured\n");
        return;
    }
    
    if (!validate_extension(client_filename)) {
        fprintf(stderr, "Invalid file type\n");
        return;
    }
    
    // 生成随机文件名，避免路径遍历
    char random_name[32];
    snprintf(random_name, sizeof(random_name), "%ld_%d", time(NULL), rand());
    
    snprintf(safe_path, sizeof(safe_path), "%s/%s%s", 
             UPLOAD_DIR, random_name, 
             strrchr(client_filename, '.'));  // 只取扩展名
    
    FILE *fp = fopen(safe_path, "wb");
    if (!fp) {
        perror("fopen");
        return;
    }
    
    // 假设从客户端读取数据流写入
    fprintf(fp, "Uploaded content");
    fclose(fp);
    
    // 设置最小权限
    chmod(safe_path, 0640);
    printf("File saved to %s\n", safe_path);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    process_upload(argv[1]);
    return 0;
}

