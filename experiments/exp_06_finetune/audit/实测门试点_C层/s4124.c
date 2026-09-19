#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DATA_SIZE 1024
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while (0)

typedef struct {
    char *buffer;
    size_t length;
} DataBuffer;

static int init_buffer(DataBuffer *db, size_t size) {
    if (!db || size == 0 || size > MAX_DATA_SIZE) {
        return -1;
    }
    db->buffer = (char *)malloc(size);
    if (!db->buffer) {
        return -1;
    }
    db->length = size;
    memset(db->buffer, 0, size);
    return 0;
}

static void destroy_buffer(DataBuffer *db) {
    if (db) {
        SAFE_FREE(db->buffer);
        db->length = 0;
    }
}

static int copy_to_buffer(DataBuffer *db, const char *src, size_t src_len) {
    if (!db || !src || !db->buffer) {
        return -1;
    }
    if (src_len >= db->length) {
        return -1;
    }
    memcpy(db->buffer, src, src_len);
    db->buffer[src_len] = '\0';
    return 0;
}

int main(int argc, char *argv[]) {
    DataBuffer db;
    memset(&db, 0, sizeof(db));

    if (init_buffer(&db, 256) != 0) {
        fprintf(stderr, "Buffer init failed\n");
        return 1;
    }

    const char *user_input = "Hello, secure world!";
    size_t input_len = strlen(user_input);

    if (copy_to_buffer(&db, user_input, input_len) != 0) {
        fprintf(stderr, "Copy failed\n");
        destroy_buffer(&db);
        return 1;
    }

    printf("Buffer content: %s\n", db.buffer);
    destroy_buffer(&db);
    return 0;
}

