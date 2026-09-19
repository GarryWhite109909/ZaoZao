
#include <stdio.h>
#include <string.h>

void greet(char *user) {
    char buf[16];
    strcpy(buf, user);   // 无边界复制
    printf("Hello %s\n", buf);
}

int main(int argc, char **argv) {
    greet(argv[1]);
    return 0;
}

