#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define MAX_PATH 256
#define ORDERS_DIR "/var/data/orders"

/**
 * 根据订单号加载订单详情文件
 * 订单文件命名规则: {order_id}.json
 */
char* load_order_detail(const char* order_id) {
    char filepath[MAX_PATH];
    char* content = NULL;
    FILE* fp = NULL;
    long fsize;
    
    // 拼接订单文件路径
    snprintf(filepath, sizeof(filepath), "%s/%s.json", ORDERS_DIR, order_id);
    
    // 打开文件
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        return NULL;
    }
    
    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // 读取文件内容
    content = (char*)malloc(fsize + 1);
    if (content == NULL) {
        fclose(fp);
        return NULL;
    }
    
    size_t bytes_read = fread(content, 1, fsize, fp);
    content[bytes_read] = '\0';
    fclose(fp);
    
    return content;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <order_id>\n", argv[0]);
        return 1;
    }
    
    char* detail = load_order_detail(argv[1]);
    if (detail == NULL) {
        printf("Order not found\n");
        return 1;
    }
    
    printf("Order detail: %s\n", detail);
    free(detail);
    
    return 0;
}

