#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_PATH 256

typedef struct {
    char user_id[32];
    char session_token[64];
    char data_path[MAX_PATH];
} SessionData;

int load_session(const char* base_dir, const char* user_input) {
    char full_path[MAX_PATH];
    SessionData session;
    int fd;

    // 模拟从用户输入获取会话文件名（如 "alice_sess.dat"）
    snprintf(session.data_path, sizeof(session.data_path), "%s", user_input);

    // 构造完整路径：/var/sessions/<user_input>
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, session.data_path);

    // 打开文件读取会话数据
    fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return -1;
    }

    // 读取数据（简化：只读前 100 字节）
    if (read(fd, &session, sizeof(session)) != sizeof(session)) {
        close(fd);
        return -1;
    }
    close(fd);

    // 模拟使用 session 数据
    printf("User: %s, Path: %s\n", session.user_id, session.data_path);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <session_file>\n", argv[0]);
        return 1;
    }
    return load_session("/var/sessions", argv[1]);
}

