// chunk_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CHUNK_SIZE 8192

int send_chunks(const char *data, size_t total_len) {
    if (data == NULL) return -1;
    size_t sent = 0;
    while (sent < total_len) {
        size_t remaining = total_len - sent;
        size_t this_chunk = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
        fwrite(data + sent, 1, this_chunk, stdout);
        sent += this_chunk;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    send_chunks(argv[1], strlen(argv[1]));
    return 0;
}

