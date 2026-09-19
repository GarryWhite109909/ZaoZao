#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH_LEN 256
#define MAX_ORDERS 100

typedef struct {
    int order_id;
    char customer[64];
    char item[64];
    float amount;
} Order;

// 模拟订单数据库
static Order orders[MAX_ORDERS] = {
    {1001, "alice", "laptop", 899.99},
    {1002, "bob", "mouse", 12.50},
    {1003, "carol", "keyboard", 45.00}
};
static int order_count = 3;

// 根据订单ID生成报告文件路径
char* build_report_path(const char* order_id_str) {
    char* path = (char*)malloc(MAX_PATH_LEN);
    if (!path) return NULL;

    snprintf(path, MAX_PATH_LEN, "/var/order_reports/%s.txt", order_id_str);
    return path;
}

// 读取订单报告内容
void read_order_report(const char* order_id_str) {
    char* filepath = build_report_path(order_id_str);
    if (!filepath) {
        printf("Memory allocation failed\n");
        return;
    }

    FILE* fp = fopen(filepath, "r");
    if (fp == NULL) {
        printf("Report not found for order: %s\n", order_id_str);
        free(filepath);
        return;
    }

    char buffer[512];
    printf("=== Order Report ===\n");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    printf("====================\n");

    fclose(fp);
    free(filepath);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <order_id>\n", argv[0]);
        return 1;
    }

    read_order_report(argv[1]);
    return 0;
}

