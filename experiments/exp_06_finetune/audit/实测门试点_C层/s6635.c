/* C 服务：先 access 检查权限再 open，存在 TOCTOU 竞争 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int read_secret(const char* path) {
    /* 漏洞：access 和 open 之间存在时间窗口 */
    if (access(path, R_OK) != 0) {        // line 7: 检查点
        return -1;
    }
    /* 攻击者在此窗口内把 path 替换为 /etc/shadow 的符号链接 */
    int fd = open(path, O_RDONLY);        // line 11: 使用点
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) write(STDOUT_FILENO, buf, n);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    return read_secret(argv[1]);          // line 22: 用户可控 path
}
