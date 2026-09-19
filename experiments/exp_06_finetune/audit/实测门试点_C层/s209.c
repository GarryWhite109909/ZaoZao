#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_BUF 256

/* 模拟全局配置结构 */
typedef struct {
    char *data;
    size_t len;
} ConfigEntry;

static ConfigEntry *global_config = NULL;

/* 加载配置：在特权上下文（如setuid程序）中调用，读取敏感数据 */
int load_config(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    
    char buf[MAX_BUF];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    
    /* 分配并存储配置 */
    global_config = malloc(sizeof(ConfigEntry));
    if (!global_config) return -1;
    global_config->data = strdup(buf);
    global_config->len = n;
    return 0;
}

/* 释放配置：在非特权上下文（如用户请求处理）中调用 */
void free_config(void) {
    if (global_config) {
        free(global_config->data);
        free(global_config);
        /* 漏洞：未将global_config置为NULL */
    }
}

/* 重新加载配置：模拟配置更新流程 */
int reload_config(const char *path) {
    free_config();  /* 第一次释放，global_config变为悬垂指针 */
    /* 此时global_config仍指向已释放的内存 */
    return load_config(path);  /* 若load_config失败，悬垂指针保留 */
}

/* 读取配置项（后续可能被外部调用） */
const char *get_config_data(void) {
    if (global_config) {
        return global_config->data;  /* 悬垂指针解引用 */
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_path>\n", argv[0]);
        return 1;
    }
    
    if (load_config(argv[1]) != 0) {
        fprintf(stderr, "Initial load failed\n");
        return 1;
    }
    printf("Initial config: %s\n", get_config_data());
    
    /* 模拟配置更新：先free再load */
    if (reload_config(argv[1]) != 0) {
        fprintf(stderr, "Reload failed\n");
        /* 漏洞触发路径：reload失败时，global_config为悬垂指针 */
    }
    
    /* 在reload失败后调用get_config_data，触发use-after-free */
    const char *data = get_config_data();
    if (data) {
        printf("Config after reload: %s\n", data);
    } else {
        printf("No config available\n");
    }
    
    /* 程序结束时再次free，导致double-free */
    free_config();
    return 0;
}

