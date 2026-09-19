#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t *payload;
    size_t len;
} Packet;

typedef struct {
    Packet *pkt;
    int parsed;
} Session;

void parse_packet(Session *sess, const uint8_t *data, size_t size) {
    if (size < 4) return;
    uint16_t pkt_len = (data[0] << 8) | data[1];
    if (pkt_len > size - 2) return;

    sess->pkt->payload = (uint8_t *)malloc(pkt_len);
    if (!sess->pkt->payload) return;
    memcpy(sess->pkt->payload, data + 2, pkt_len);
    sess->pkt->len = pkt_len;
    sess->parsed = 1;
}

void cleanup_session(Session *sess) {
    if (sess->pkt && sess->pkt->payload) {
        free(sess->pkt->payload);
        // 注意：此处未将 payload 置为 NULL
    }
}

int process_network_data(Session *sess, const uint8_t *buf, size_t buf_size) {
    if (!sess || !sess->pkt) return -1;

    parse_packet(sess, buf, buf_size);
    if (!sess->parsed) {
        cleanup_session(sess);
        return -1;
    }

    // 模拟后续处理：再次访问 payload
    if (sess->pkt->payload[0] == 0xFF) {   // 潜在 UAF：若 parse 失败且 cleanup 已释放
        printf("special packet\n");
    }
    return 0;
}

int main() {
    Session sess;
    sess.pkt = (Packet *)malloc(sizeof(Packet));
    if (!sess.pkt) return 1;
    sess.pkt->payload = NULL;
    sess.pkt->len = 0;
    sess.parsed = 0;

    uint8_t bad_data[4] = {0x00, 0x00, 0x00, 0x00}; // pkt_len=0, 但 size>=4
    process_network_data(&sess, bad_data, 4);

    free(sess.pkt);
    return 0;
}

