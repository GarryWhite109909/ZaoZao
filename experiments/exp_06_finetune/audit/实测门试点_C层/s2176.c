// CVE-style: Sudo 1.8.0-1.8.3p1 (CVE-2012-0809) sudo_debug 格式串漏洞
// 简化：argv[0] 被当作格式串传递给 fprintf
#include <stdio.h>

void debug_log(char *argv0) {
    fprintf(stderr, argv0);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    debug_log(argv[0]);
    return 0;
}

