#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PKT_SIZE 1024
#define MAX_FIELD_SIZE 128

typedef struct {
    uint8_t *data;
    size_t len;
    size_t pos;
} PacketReader;

int read_field(PacketReader *reader, char *out, size_t out_size) {
    if (reader == NULL || out == NULL || out_size == 0) {
        return -1;
    }
    
    // Check remaining data is sufficient for at least 1 byte + terminator
    if (reader->pos >= reader->len) {
        return -2;
    }
    
    size_t field_len = 0;
    size_t max_readable = reader->len - reader->pos;
    size_t copy_limit = (max_readable < out_size - 1) ? max_readable : (out_size - 1);
    
    // Copy field data with explicit bounds check
    while (field_len < copy_limit && reader->data[reader->pos + field_len] != '\n') {
        out[field_len] = reader->data[reader->pos + field_len];
        field_len++;
    }
    
    // Terminate string
    out[field_len] = '\0';
    
    // Advance position past field (including newline if present)
    if (field_len < max_readable && reader->data[reader->pos + field_len] == '\n') {
        reader->pos += field_len + 1;
    } else {
        reader->pos += field_len;
    }
    
    return (int)field_len;
}

int parse_packet(const uint8_t *packet, size_t packet_len) {
    if (packet == NULL || packet_len == 0 || packet_len > MAX_PKT_SIZE) {
        return -1;
    }
    
    PacketReader reader = { (uint8_t *)packet, packet_len, 0 };
    char username[MAX_FIELD_SIZE];
    char password[MAX_FIELD_SIZE];
    
    // Parse username field
    int user_len = read_field(&reader, username, sizeof(username));
    if (user_len < 0) {
        return -2;
    }
    
    // Parse password field
    int pass_len = read_field(&reader, password, sizeof(password));
    if (pass_len < 0) {
        return -3;
    }
    
    // Validate fields are non-empty
    if (user_len == 0 || pass_len == 0) {
        return -4;
    }
    
    printf("Login: %s / %s\n", username, password);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <packet>\n", argv[0]);
        return 1;
    }
    
    size_t len = strlen(argv[1]);
    if (len > MAX_PKT_SIZE) {
        fprintf(stderr, "Packet too large\n");
        return 1;
    }
    
    return parse_packet((const uint8_t *)argv[1], len);
}

