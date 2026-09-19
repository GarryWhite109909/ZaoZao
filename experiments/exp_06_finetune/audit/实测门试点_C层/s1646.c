#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    char username[32];
    char session_data[256];
} UserSession;

int serialize_session(const char* username, const char* data, char* out_path) {
    char dir_path[64];
    char full_path[128];
    UserSession session;
    
    /* 构造用户目录路径 */
    snprintf(dir_path, sizeof(dir_path), "/tmp/sessions/%s", username);
    
    /* 确保目录存在 */
    mkdir(dir_path, 0700);
    
    /* 生成完整文件路径 */
    snprintf(full_path, sizeof(full_path), "%s/session.dat", dir_path);
    
    /* 填充会话数据 */
    memset(&session, 0, sizeof(session));
    strncpy(session.username, username, sizeof(session.username) - 1);
    strncpy(session.session_data, data, sizeof(session.session_data) - 1);
    
    /* 写入序列化数据 */
    int fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    
    ssize_t written = write(fd, &session, sizeof(session));
    close(fd);
    
    if (written != sizeof(session)) {
        return -1;
    }
    
    /* 复制路径供外部使用 */
    strcpy(out_path, full_path);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <username> <data>\n", argv[0]);
        return 1;
    }
    
    char result_path[128];
    if (serialize_session(argv[1], argv[2], result_path) == 0) {
        printf("Session saved to: %s\n", result_path);
    }
    return 0;
}

