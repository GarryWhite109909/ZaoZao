#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_BUF 256
#define CONFIG_PATH "/etc/firmware/config"

typedef struct {
    char *data;
    size_t size;
} buffer_t;

static int load_config(buffer_t *out) {
    int fd = open(CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    char stack_buf[MAX_BUF];
    ssize_t n = read(fd, stack_buf, sizeof(stack_buf) - 1);
    close(fd);
    
    if (n <= 0) {
        return -1;
    }
    stack_buf[n] = '\0';
    
    out->data = (char *)malloc(n + 1);
    if (out->data == NULL) {
        return -1;
    }
    memcpy(out->data, stack_buf, n + 1);
    out->size = n;
    return 0;
}

static void process_config(buffer_t *cfg) {
    if (cfg == NULL || cfg->data == NULL) {
        return;
    }
    
    /* 安全处理：使用长度字段，而非依赖字符串终止符 */
    for (size_t i = 0; i < cfg->size; i++) {
        if (cfg->data[i] == '\n') {
            cfg->data[i] = '\0';
            break;
        }
    }
}

int main(void) {
    buffer_t cfg = {0};
    
    if (load_config(&cfg) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }
    
    process_config(&cfg);
    
    /* 安全释放：free后置NULL，防止悬垂指针 */
    free(cfg.data);
    cfg.data = NULL;
    cfg.size = 0;
    
    return 0;
}

