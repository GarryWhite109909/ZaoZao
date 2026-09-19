/* C Web 服务：解析配置文件，错误路径未 free 堆内存 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* load_config(const char* path) {
    FILE* f = fopen(path, "r");            // line 7
    if (!f) return NULL;
    char* buf = malloc(8192);              // line 9
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, 8191, f);     // line 11
    if (n == 0) {
        /* 漏洞：fread 失败时直接返回，未 free(buf) */
        fclose(f);
        return NULL;                       // line 15 -> buf 泄漏
    }
    buf[n] = '\0';
    fclose(f);
    return buf;                            // line 19 -> 调用方需 free
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* cfg = load_config(argv[i]);   // line 23
        if (cfg) printf("%s\n", cfg);
        /* 漏洞：cfg 使用后未 free，每轮循环泄漏 8KB */
    }
    return 0;
}
