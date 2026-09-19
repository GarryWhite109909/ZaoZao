#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PATH 256
#define ORDER_DIR "/var/data/orders/"

/* 根据订单ID读取订单详情文件 */
char* read_order_file(const char* order_id) {
    char filepath[MAX_PATH];
    char* content = NULL;
    FILE* fp;
    long size;
    
    /* 拼接订单文件路径 */
    snprintf(filepath, sizeof(filepath), "%s%s.txt", ORDER_DIR, order_id);
    
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        return NULL;
    }
    
    /* 获取文件大小 */
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    /* 分配内存并读取文件 */
    content = (char*)malloc(size + 1);
    if (content == NULL) {
        fclose(fp);
        return NULL;
    }
    
    fread(content, 1, size, fp);
    content[size] = '\0';
    fclose(fp);
    
    return content;
}

int main(int argc, char* argv[]) {
    char* order_id;
    char* order_content;
    
    if (argc < 2) {
        printf("Usage: %s <order_id>\n", argv[0]);
        return 1;
    }
    
    order_id = argv[1];
    
    /* 查询订单 */
    order_content = read_order_file(order_id);
    if (order_content == NULL) {
        printf("Order not found: %s\n", order_id);
        return 1;
    }
    
    printf("Order details:\n%s\n", order_content);
    free(order_content);
    
    return 0;
}

