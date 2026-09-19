#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 32

typedef struct {
    char data[MAX_BUF];
    int len;
} Buffer;

void process_input(FILE *fp) {
    Buffer buf;
    char *temp = NULL;
    size_t read_len;
    
    memset(&buf, 0, sizeof(buf));
    
    // Read header
    if (fread(&buf.len, sizeof(int), 1, fp) != 1) {
        printf("Failed to read length\n");
        return;
    }
    
    // Validate length against buffer capacity
    if (buf.len < 0 || buf.len >= MAX_BUF) {
        printf("Invalid length: %d\n", buf.len);
        return;
    }
    
    // Read data into stack buffer
    read_len = fread(buf.data, 1, buf.len, fp);
    if (read_len != (size_t)buf.len) {
        printf("Short read\n");
        return;
    }
    
    buf.data[buf.len] = '\0';  // Null terminate
    
    // Copy to heap for further processing
    temp = (char *)malloc(buf.len + 1);
    if (!temp) {
        printf("Malloc failed\n");
        return;
    }
    
    memcpy(temp, buf.data, buf.len + 1);
    printf("Processed: %s\n", temp);
    
    free(temp);
}

int main(int argc, char *argv[]) {
    FILE *fp;
    
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }
    
    fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Cannot open file\n");
        return 1;
    }
    
    process_input(fp);
    fclose(fp);
    return 0;
}

