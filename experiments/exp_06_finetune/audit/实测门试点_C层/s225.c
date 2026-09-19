#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_FIELD_LEN 64
#define MAX_MSG_LEN 256

typedef struct {
    char type[8];
    char payload[MAX_MSG_LEN];
    uint16_t payload_len;
} NetMsg;

int parse_net_msg(const char *buffer, size_t buf_size, NetMsg *out) {
    if (buf_size < 10) return -1;
    
    // 提取消息类型（前8字节）
    memcpy(out->type, buffer, 8);
    out->type[7] = '\0';
    
    // 提取payload长度（第9-10字节，大端序）
    out->payload_len = (uint16_t)((buffer[8] << 8) | buffer[9]);
    
    // 检查payload长度是否超过缓冲区剩余大小
    if (out->payload_len > buf_size - 10) {
        return -2;
    }
    
    // 复制payload
    memcpy(out->payload, buffer + 10, out->payload_len);
    out->payload[out->payload_len] = '\0';
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    char buffer[MAX_MSG_LEN + 10];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (bytes_read == 0) {
        printf("Empty file\n");
        return 1;
    }
    
    NetMsg msg;
    memset(&msg, 0, sizeof(msg));
    
    int ret = parse_net_msg(buffer, bytes_read, &msg);
    if (ret != 0) {
        printf("Parse error: %d\n", ret);
        return 1;
    }
    
    printf("Type: %s, Len: %u\n", msg.type, msg.payload_len);
    printf("Payload: %s\n", msg.payload);
    
    return 0;
}

