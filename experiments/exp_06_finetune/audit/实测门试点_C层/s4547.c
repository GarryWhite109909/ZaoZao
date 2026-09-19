#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buffer;
    size_t len;
} Packet;

typedef struct {
    Packet *pkt;
    int valid;
} PacketHandle;

/* 安全释放：free后置NULL，防止悬垂指针 */
void packet_free(Packet **pp) {
    if (pp && *pp) {
        free((*pp)->buffer);
        (*pp)->buffer = NULL;
        free(*pp);
        *pp = NULL;
    }
}

/* 解析数据包，成功返回0，失败返回-1 */
int parse_packet(PacketHandle *handle, const char *raw, size_t raw_len) {
    if (!handle || !raw || raw_len < 2) {
        return -1;
    }

    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    if (!pkt) {
        return -1;
    }

    pkt->len = raw_len;
    pkt->buffer = (char *)malloc(raw_len);
    if (!pkt->buffer) {
        free(pkt);
        return -1;
    }

    memcpy(pkt->buffer, raw, raw_len);

    handle->pkt = pkt;
    handle->valid = 1;
    return 0;
}

/* 固件命令处理：解析后立即消费，不保留引用 */
int process_command(PacketHandle *handle) {
    if (!handle || !handle->valid || !handle->pkt) {
        return -1;
    }

    /* 消费数据 */
    size_t len = handle->pkt->len;
    char *buf = handle->pkt->buffer;

    /* 模拟数据处理 */
    if (len > 0 && buf[0] == 0xAA) {
        /* 处理逻辑 */
    }

    /* 处理完成后立即释放并置空 */
    packet_free(&handle->pkt);
    handle->valid = 0;
    return 0;
}

int main(void) {
    const char raw_data[] = {0xAA, 0x01, 0x02};
    PacketHandle handle = {0};

    if (parse_packet(&handle, raw_data, sizeof(raw_data)) != 0) {
        return -1;
    }

    /* 使用handle */
    if (process_command(&handle) != 0) {
        return -1;
    }

    /* 尝试再次使用（防御验证：valid标志阻止） */
    if (process_command(&handle) != 0) {
        /* 预期失败，安全 */
    }

    return 0;
}

