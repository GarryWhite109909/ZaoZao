#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define MAX_ORDER_ID 32

// 模拟从外部获取订单ID的函数
const char* get_order_id_from_request() {
    // 实际场景中，这里会从HTTP请求或命令行参数获取
    return "../../../etc/passwd";
}

// 模拟文件读取函数
void read_order_file(const char* filename) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "/var/orders/%s", filename);
    
    FILE* fp = fopen(full_path, "r");
    if (fp == NULL) {
        printf("Order file not found: %s\n", full_path);
        return;
    }
    
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    fclose(fp);
}

int main() {
    const char* order_id = get_order_id_from_request();
    
    // 只做基本长度检查，未过滤路径分隔符
    if (strlen(order_id) < MAX_ORDER_ID) {
        read_order_file(order_id);
    } else {
        printf("Invalid order ID\n");
    }
    
    return 0;
}

