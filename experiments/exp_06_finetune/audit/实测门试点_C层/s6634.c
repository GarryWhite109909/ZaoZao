/* C 服务：goto cleanup 模式确保所有路径释放资源 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* load_config(const char* path) {
    char* buf = NULL;
    FILE* f = fopen(path, "r");          // line 7
    if (!f) return NULL;
    buf = malloc(8192);                  // line 10
    if (!buf) goto cleanup_f;
    size_t n = fread(buf, 1, 8191, f);   // line 12
    if (n == 0) goto cleanup_buf;       /* 失败也走 cleanup，统一释放 */
    buf[n] = '\0';
    fclose(f);
    return buf;                          /* 成功：所有权转移给调用方 */
cleanup_buf:
    free(buf);                           /* line 18: 失败路径释放 buf */
cleanup_f:
    fclose(f);                           /* line 20: 失败路径关闭 f */
    return NULL;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* cfg = load_config(argv[i]);  /* line 25 */
        if (cfg) {
            printf("%s\n", cfg);
            free(cfg);                    /* line 28: 使用完立即释放 */
        }
    }
    return 0;
}
