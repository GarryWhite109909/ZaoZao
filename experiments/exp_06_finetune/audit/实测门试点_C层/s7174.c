
#include <stdio.h>
#include <unistd.h>

int main() {
    // 以 root 打开敏感文件后未 drop
    FILE *f = fopen("/etc/shadow", "r");
    // 未调用 setuid(getuid()) 降权
    char line[256];
    fgets(line, sizeof(line), f);
    puts(line);
    return 0;
}

