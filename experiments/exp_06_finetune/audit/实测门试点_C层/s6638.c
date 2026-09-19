/* C 服务：在 /tmp 创建日志文件，存在符号链接竞争 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void write_log(const char* msg) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/log_%d.txt", getpid());  // line 8
    /* 漏洞：先 unlink，再 fopen，攻击者可在中间插入符号链接 */
    unlink(path);                                   // line 11: 检查点
    FILE* f = fopen(path, "w");                     // line 12: 使用点
    if (!f) return;
    fprintf(f, "%s\n", msg);
    fclose(f);
}

int main() {
    write_log("service started");                   // line 19
    return 0;
}
