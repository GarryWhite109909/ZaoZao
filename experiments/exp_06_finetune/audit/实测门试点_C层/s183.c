#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 64
#define COPY_SAFE(dst, src, size) \
    do { \
        if (strlen(src) >= (size)) { \
            fprintf(stderr, "Copy overflow prevented\n"); \
            return -1; \
        } \
        strcpy((dst), (src)); \
    } while (0)

static void process_data(const char *input, char *output, size_t out_size) {
    char temp[MAX_BUF];
    size_t len = strlen(input);
    
    if (len < MAX_BUF) {
        strcpy(temp, input);  // line 16: safe copy (len < 64)
    } else {
        return;
    }
    
    // Simulate complex transformation
    for (size_t i = 0; i < len; i++) {
        temp[i] = (char)(temp[i] ^ 0x5A);
    }
    
    memcpy(output, temp, len);  // line 26: potential overflow if out_size < len
}

int handle_request(const char *user_input, char *response, size_t resp_len) {
    if (user_input == NULL || response == NULL) {
        return -1;
    }
    
    char local_buf[MAX_BUF];
    COPY_SAFE(local_buf, user_input, MAX_BUF);  // line 34: macro boundary check
    
    // Cross-function call with implicit size assumption
    process_data(local_buf, response, resp_len);  // line 37: resp_len passed but not validated
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    char response[32];  // line 45: small buffer, only 32 bytes
    if (handle_request(argv[1], response, sizeof(response)) == 0) {
        printf("Response: %s\n", response);
    }
    return 0;
}

