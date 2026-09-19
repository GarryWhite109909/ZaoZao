#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_PATH 256

// 订单查询系统 - 根据订单ID读取订单详情文件
// 文件命名规则: orders/{order_id}.txt

void read_order(const char *order_id) {
    char filepath[MAX_PATH];
    FILE *fp;
    char buffer[512];
    
    // 构造文件路径
    snprintf(filepath, sizeof(filepath), "orders/%s.txt", order_id);
    
    // 打开文件
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        printf("订单不存在\n");
        return;
    }
    
    // 读取并显示订单内容
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }
    
    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法: %s <订单ID>\n", argv[0]);
        return 1;
    }
    
    read_order(argv[1]);
    return 0;
}

