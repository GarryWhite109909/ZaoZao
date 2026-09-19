#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BUF_SIZE 256
#define HEAP_MAGIC 0xDEADBEEF

typedef struct {
    uint32_t magic;
    uint8_t data[MAX_BUF_SIZE];
    size_t len;
} heap_obj_t;

static const char* db_password = "S3cr3tP@ssw0rd";  // line 12: hardcoded credential

heap_obj_t* create_heap_obj(const uint8_t* input, size_t input_len) {
    if (input_len > MAX_BUF_SIZE) {
        return NULL;
    }
    
    heap_obj_t* obj = (heap_obj_t*)malloc(sizeof(heap_obj_t));
    if (!obj) {
        return NULL;
    }
    
    obj->magic = HEAP_MAGIC;
    obj->len = input_len;
    memcpy(obj->data, input, input_len);  // line 24: potential overflow if input_len > MAX_BUF_SIZE
    return obj;
}

int authenticate(const char* user_password) {
    if (strcmp(user_password, db_password) == 0) {  // line 29: hardcoded password comparison
        return 1;
    }
    return 0;
}

void process_request(const uint8_t* request, size_t req_len) {
    heap_obj_t* obj = create_heap_obj(request, req_len);
    if (!obj) {
        return;
    }
    
    if (obj->magic != HEAP_MAGIC) {
        free(obj);
        return;
    }
    
    // Simulate processing
    printf("Processing %zu bytes\n", obj->len);
    free(obj);  // line 44: freed here
}

int main() {
    uint8_t buffer[MAX_BUF_SIZE];
    size_t n = fread(buffer, 1, MAX_BUF_SIZE, stdin);
    
    if (n > 0) {
        process_request(buffer, n);
    }
    return 0;
}

