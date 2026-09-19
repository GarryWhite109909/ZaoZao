#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_BUF 256
#define CONFIG_PATH "/tmp/app_config"

/* 模拟全局配置缓存 */
static char *g_config_cache = NULL;
static size_t g_cache_len = 0;

/* 从文件读取配置到堆缓冲区 */
static int load_config_from_file(const char *path, char **out_buf, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    
    char *buf = (char *)malloc(st.st_size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    
    ssize_t n = read(fd, buf, st.st_size);
    close(fd);
    if (n < 0) {
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    
    *out_buf = buf;
    *out_len = (size_t)n;
    return 0;
}

/* 刷新配置缓存（含TOCTOU窗口） */
static int refresh_config(void) {
    /* 第1次检查：文件是否存在 */
    struct stat st;
    if (stat(CONFIG_PATH, &st) < 0) {
        fprintf(stderr, "config not found\n");
        return -1;
    }
    
    /* 释放旧缓存 - 第8行：此处g_config_cache被free但未置NULL */
    if (g_config_cache) {
        free(g_config_cache);
        g_config_cache = NULL;  // 实际防御：置NULL（但后续仍有问题）
    }
    
    /* 第2次检查：重新stat（TOCTOU窗口） */
    if (stat(CONFIG_PATH, &st) < 0) {
        fprintf(stderr, "config disappeared\n");
        return -1;
    }
    
    /* 加载新配置 */
    char *new_buf = NULL;
    size_t new_len = 0;
    if (load_config_from_file(CONFIG_PATH, &new_buf, &new_len) < 0) {
        fprintf(stderr, "load failed\n");
        return -1;
    }
    
    g_config_cache = new_buf;
    g_cache_len = new_len;
    return 0;
}

/* 获取配置值 */
const char *get_config_value(const char *key) {
    if (!g_config_cache) return NULL;
    
    /* 简化：直接返回整个缓存 */
    return g_config_cache;
}

/* 主流程 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: %s <key>\n", argv[0]);
        return 1;
    }
    
    /* 首次加载 */
    if (refresh_config() < 0) {
        return 1;
    }
    
    /* 业务处理 */
    const char *val = get_config_value(argv[1]);
    if (val) {
        printf("value: %s\n", val);
    }
    
    /* 再次刷新（触发TOCTOU） */
    refresh_config();
    
    /* 第38行：再次使用val，但val指向的g_config_cache已被第24行释放 */
    if (val) {
        printf("value after refresh: %s\n", val);
    }
    
    /* 清理 */
    if (g_config_cache) {
        free(g_config_cache);
        g_config_cache = NULL;
    }
    return 0;
}

