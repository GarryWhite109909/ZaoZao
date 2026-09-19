/* C 服务：直接 open 后用 fstat 校验，避免 TOCTOU */
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

int read_secret(const char* path) {
    /* 安全：直接 open，不在 open 前做 access 检查 */
    int fd = open(path, O_RDONLY | O_NOFOLLOW);   /* line 7: 拒绝符号链接 */
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    /* 安全：用 fstat 检查已打开的文件描述符，而非路径 */
    if (!S_ISREG(st.st_mode)) { close(fd); return -1; }   /* line 12 */
    if (st.st_uid != getuid()) { close(fd); return -1; } /* line 13 */
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) write(STDOUT_FILENO, buf, n);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    return read_secret(argv[1]);
}
