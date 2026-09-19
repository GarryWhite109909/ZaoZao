
#include <stdio.h>

int main(int argc, char **argv) {
    char buf[32];
    printf("Enter name: ");
    gets(buf);            // gets 无边界读取
    printf("Hi %s\n", buf);
    return 0;
}

