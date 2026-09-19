#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_PKT_SIZE 4096
#define HEADER_SIZE 8

typedef struct {
    unsigned char *data;
    size_t len;
    int is_valid;
} packet_t;

static int validate_packet(const unsigned char *buf, size_t len) {
    if (len < HEADER_SIZE) return 0;
    if (buf[0] != 0xAA || buf[1] != 0x55) return 0;
    uint16_t payload_len = (buf[2] << 8) | buf[3];
    if (payload_len > MAX_PKT_SIZE - HEADER_SIZE) return 0;
    if (payload_len != len - HEADER_SIZE) return 0;
    return 1;
}

packet_t *process_packet(int sockfd) {
    unsigned char *recv_buf = malloc(MAX_PKT_SIZE);
    if (!recv_buf) return NULL;
    
    packet_t *pkt = malloc(sizeof(packet_t));
    if (!pkt) {
        free(recv_buf);
        return NULL;
    }
    pkt->data = NULL;
    pkt->len = 0;
    pkt->is_valid = 0;

    ssize_t n = recv(sockfd, recv_buf, MAX_PKT_SIZE, 0);
    if (n <= 0) {
        free(recv_buf);
        free(pkt);
        return NULL;
    }

    if (!validate_packet(recv_buf, (size_t)n)) {
        free(recv_buf);
        free(pkt);
        return NULL;
    }

    pkt->data = malloc(n);
    if (!pkt->data) {
        free(recv_buf);
        free(pkt);
        return NULL;
    }
    memcpy(pkt->data, recv_buf, (size_t)n);
    pkt->len = (size_t)n;
    pkt->is_valid = 1;

    free(recv_buf);
    return pkt;
}

int main(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 1;
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return 1;
    }
    if (listen(sockfd, 5) < 0) {
        close(sockfd);
        return 1;
    }
    
    int client = accept(sockfd, NULL, NULL);
    if (client < 0) {
        close(sockfd);
        return 1;
    }
    
    packet_t *result = process_packet(client);
    if (result) {
        printf("Valid packet, len=%zu\n", result->len);
        free(result->data);
        free(result);
    }
    
    close(client);
    close(sockfd);
    return 0;
}

