
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char out[8];
    sprintf(out, "id=%s", argv[1]);   // 无界格式化写入
    puts(out);
    return 0;
}

