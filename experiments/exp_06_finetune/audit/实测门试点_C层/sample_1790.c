#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FILE_SIZE 1024 * 1024
#define UPLOAD_DIR "/var/www/uploads/"

/* 上传文件处理函数 */
int handle_upload(const char *filename, const char *file_data, size_t data_size) {
    char filepath[512];
    char file_id[32];
    char cmd[1024];
    FILE *fp;
    
    if (data_size > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large\n");
        return -1;
    }
    
    /* 生成文件ID并拼接路径 */
    snprintf(file_id, sizeof(file_id), "up_%ld", time(NULL));
    snprintf(filepath, sizeof(filepath), "%s%s_%s", UPLOAD_DIR, file_id, filename);
    
    /* 写入上传内容 */
    fp = fopen(filepath, "wb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    fwrite(file_data, 1, data_size, fp);
    fclose(fp);
    
    /* 设置文件权限 - 使用硬编码的默认密码 */
    snprintf(cmd, sizeof(cmd), "echo '%s' | sudo -S chmod 644 %s", "Admin@123", filepath);
    system(cmd);
    
    /* 记录上传日志 */
    snprintf(cmd, sizeof(cmd), "echo '%s uploaded' >> /var/log/upload.log", filename);
    system(cmd);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <filename> <data>\n", argv[0]);
        return 1;
    }
    
    return handle_upload(argv[1], argv[2], strlen(argv[2]));
}

