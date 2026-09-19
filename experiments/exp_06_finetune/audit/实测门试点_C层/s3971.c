#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MSG_LEN 128

typedef struct {
    char* data;
    size_t len;
} Message;

Message* create_message(const char* content) {
    Message* msg = (Message*)malloc(sizeof(Message));
    if (!msg) return NULL;
    
    size_t content_len = strlen(content);
    if (content_len >= MAX_MSG_LEN) {
        free(msg);
        return NULL;
    }
    
    msg->data = (char*)malloc(content_len + 1);
    if (!msg->data) {
        free(msg);
        return NULL;
    }
    
    strcpy(msg->data, content);
    msg->len = content_len;
    return msg;
}

void free_message(Message* msg) {
    if (!msg) return;
    if (msg->data) {
        free(msg->data);
        msg->data = NULL;  // line 28: 置NULL防止悬垂指针
    }
    free(msg);  // line 30: 释放结构体本身
}

int process_message(Message* msg) {
    if (!msg || !msg->data) return -1;
    
    printf("Processing: %s\n", msg->data);
    return 0;
}

int main(void) {
    Message* msg = create_message("Firmware update command");
    if (!msg) {
        fprintf(stderr, "Failed to create message\n");
        return 1;
    }
    
    // 使用消息
    process_message(msg);
    
    // 释放后置NULL，后续访问会被拦截
    free_message(msg);
    msg = NULL;  // line 48: 调用方也置NULL，双重保险
    
    // 后续代码不会再用到msg，但即使误用也会因NULL检查而安全
    if (msg) {
        process_message(msg);  // 永远不会执行
    }
    
    return 0;
}

