#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define MAX_PACKET_SIZE 512

typedef struct {
    int sock_fd;
    char *data;
    size_t data_len;
} connection_t;

// Parse a network packet and extract the payload
int parse_packet(connection_t *conn, const char *packet, size_t packet_len) {
    if (packet_len > MAX_PACKET_SIZE) {
        return -1; // Reject oversized packets
    }
    
    // Validate packet header (first 4 bytes: length field)
    if (packet_len < 4) {
        return -1;
    }
    
    uint32_t payload_len;
    memcpy(&payload_len, packet, 4);
    payload_len = ntohl(payload_len);
    
    // Boundary check: ensure declared length matches actual packet size
    if (payload_len > packet_len - 4) {
        return -1; // Prevent out-of-bounds read
    }
    
    // Allocate buffer for payload
    conn->data = (char *)malloc(payload_len + 1);
    if (conn->data == NULL) {
        return -1;
    }
    
    // Copy payload with validated length
    memcpy(conn->data, packet + 4, payload_len);
    conn->data[payload_len] = '\0';
    conn->data_len = payload_len;
    
    return 0;
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return 1;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return 1;
    }
    
    if (listen(server_fd, 5) < 0) {
        close(server_fd);
        return 1;
    }
    
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        
        char buffer[BUFFER_SIZE];
        ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_read <= 0) {
            close(client_fd);
            continue;
        }
        
        connection_t conn = {0};
        if (parse_packet(&conn, buffer, (size_t)bytes_read) == 0) {
            // Process payload (e.g., log it)
            printf("Received: %s\n", conn.data);
            free(conn.data);
            conn.data = NULL;
        } else {
            printf("Invalid packet\n");
        }
        
        close(client_fd);
    }
    
    close(server_fd);
    return 0;
}

