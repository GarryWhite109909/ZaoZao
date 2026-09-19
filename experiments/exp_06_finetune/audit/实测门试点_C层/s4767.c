#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 64
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)

typedef struct {
    int id;
    char *data;
} record_t;

static int process_record(record_t *rec, const char *input, size_t len) {
    if (!rec || !input || len == 0) return -1;
    if (len > MAX_BUF_SIZE) return -2;

    char *tmp = (char *)malloc(len + 1);
    if (!tmp) return -3;
    memcpy(tmp, input, len);
    tmp[len] = '\0';

    if (rec->data) {
        SAFE_FREE(rec->data);
    }
    rec->data = tmp;
    return 0;
}

static void destroy_record(record_t *rec) {
    if (rec) {
        SAFE_FREE(rec->data);
        rec->id = 0;
    }
}

int main(void) {
    record_t rec = {0, NULL};
    char input[MAX_BUF_SIZE + 1];

    printf("Enter data (max %d chars): ", MAX_BUF_SIZE);
    if (!fgets(input, sizeof(input), stdin)) return 1;
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
        len--;
    }

    if (process_record(&rec, input, len) != 0) {
        fprintf(stderr, "Failed to process record\n");
        destroy_record(&rec);
        return 1;
    }

    printf("Record ID: %d, Data: %s\n", rec.id, rec.data);
    destroy_record(&rec);
    return 0;
}

