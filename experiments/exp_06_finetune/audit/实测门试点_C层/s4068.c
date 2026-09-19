#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_LEN 1024
#define MAX_FIELDS 8

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} Buffer;

int parse_packet(const uint8_t *packet, size_t packet_len, char **fields, size_t *num_fields) {
    if (packet == NULL || packet_len == 0 || packet_len > MAX_PACKET_LEN) {
        return -1;
    }

    Buffer buf;
    buf.data = (uint8_t *)malloc(packet_len);
    if (buf.data == NULL) {
        return -1;
    }
    buf.len = packet_len;
    buf.capacity = packet_len;
    memcpy(buf.data, packet, packet_len);

    size_t field_count = 0;
    size_t offset = 0;

    while (offset < buf.len && field_count < MAX_FIELDS) {
        // Find delimiter (comma)
        size_t delim_pos = offset;
        while (delim_pos < buf.len && buf.data[delim_pos] != ',') {
            delim_pos++;
        }

        size_t field_len = delim_pos - offset;
        char *field = (char *)malloc(field_len + 1);
        if (field == NULL) {
            free(buf.data);
            buf.data = NULL;
            for (size_t i = 0; i < field_count; i++) {
                free(fields[i]);
                fields[i] = NULL;
            }
            return -1;
        }

        memcpy(field, buf.data + offset, field_len);
        field[field_len] = '\0';
        fields[field_count] = field;
        field_count++;

        if (delim_pos == buf.len) {
            break;
        }
        offset = delim_pos + 1;
    }

    free(buf.data);
    buf.data = NULL;

    if (field_count == 0) {
        return -1;
    }

    *num_fields = field_count;
    return 0;
}

int main() {
    uint8_t packet[] = "id=123,name=admin,role=user";
    char *fields[MAX_FIELDS] = {0};
    size_t num_fields = 0;

    if (parse_packet(packet, sizeof(packet) - 1, fields, &num_fields) == 0) {
        for (size_t i = 0; i < num_fields; i++) {
            printf("Field %zu: %s\n", i, fields[i]);
            free(fields[i]);
            fields[i] = NULL;
        }
    }

    return 0;
}

