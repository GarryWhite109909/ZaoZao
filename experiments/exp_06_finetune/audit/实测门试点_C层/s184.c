#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int type;
    char *data;
} Packet;

typedef struct {
    Packet *pkt;
    int processed;
} Conn;

void free_packet(Packet *p) {
    if (p) {
        free(p->data);
        free(p);
    }
}

void process_data(Conn *conn) {
    if (conn->processed) {
        return;
    }
    printf("Processing packet type %d\n", conn->pkt->type);  // line 18
    conn->processed = 1;
}

void cleanup_conn(Conn *conn) {
    if (conn->pkt) {
        free_packet(conn->pkt);
        conn->pkt = NULL;
    }
    conn->processed = 0;
}

void handle_timeout(Conn *conn) {
    cleanup_conn(conn);
    process_data(conn);  // line 31: UAF - conn->pkt is freed but not checked
}

int main() {
    Conn conn;
    conn.pkt = (Packet *)malloc(sizeof(Packet));
    if (!conn.pkt) return 1;
    conn.pkt->data = (char *)malloc(16);
    if (!conn.pkt->data) {
        free(conn.pkt);
        return 1;
    }
    strcpy(conn.pkt->data, "hello");
    conn.pkt->type = 1;
    conn.processed = 0;

    handle_timeout(&conn);
    return 0;
}

