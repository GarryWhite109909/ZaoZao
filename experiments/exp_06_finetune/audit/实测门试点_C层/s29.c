#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 32

typedef struct {
    char data[BUFFER_SIZE];
    int len;
} Buffer;

void process_input(Buffer *buf, const char *input) {
    size_t input_len = strlen(input);
    
    if (input_len > BUFFER_SIZE) {
        printf("Input too long\n");
        return;
    }
    
    memcpy(buf->data, input, input_len);
    buf->data[input_len] = '\0';
    buf->len = (int)input_len;
}

void vulnerable_copy(char *dst, const char *src) {
    strcpy(dst, src);  // line 21: 无边界检查的字符串拷贝
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    Buffer buf;
    memset(&buf, 0, sizeof(buf));
    
    process_input(&buf, argv[1]);
    printf("Processed: %s\n", buf.data);
    
    char local_buf[16];  // line 34: 小缓冲区
    vulnerable_copy(local_buf, argv[1]);  // line 35: 触发栈溢出
    
    return 0;
}

