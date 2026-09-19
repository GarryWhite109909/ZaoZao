#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define MAX_ORDERS 100

typedef struct {
    char order_id[32];
    char customer[64];
    float amount;
} Order;

/* 根据订单号生成报表文件路径 */
static char* build_report_path(const char* order_id) {
    char* path = (char*)malloc(MAX_PATH);
    if (!path) return NULL;
    
    snprintf(path, MAX_PATH, "/var/reports/%s.txt", order_id);
    return path;
}

/* 读取订单报表并打印 */
void print_order_report(const char* user_input) {
    char order_id[32];
    char* path;
    FILE* fp;
    char buffer[256];
    
    /* 从用户输入提取订单号 */
    strncpy(order_id, user_input, sizeof(order_id) - 1);
    order_id[sizeof(order_id) - 1] = '\0';
    
    /* 去除换行符 */
    order_id[strcspn(order_id, "\n")] = 0;
    
    path = build_report_path(order_id);
    if (!path) {
        printf("内存分配失败\n");
        return;
    }
    
    /* 打开并读取报表文件 */
    fp = fopen(path, "r");
    if (!fp) {
        printf("订单报表不存在: %s\n", path);
        free(path);
        return;
    }
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("%s", buffer);
    }
    
    fclose(fp);
    free(path);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("用法: %s <订单号>\n", argv[0]);
        return 1;
    }
    
    print_order_report(argv[1]);
    return 0;
}

