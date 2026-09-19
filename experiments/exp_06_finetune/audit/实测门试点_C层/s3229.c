#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 固件配置结构体 */
typedef struct {
    uint8_t magic;
    uint16_t fw_version;
    uint32_t crc;
} fw_header_t;

/* 固件映像管理 */
static fw_header_t *g_fw_header = NULL;
static uint8_t *g_fw_data = NULL;
static size_t g_fw_size = 0;

/* 安全释放函数：置NULL防止悬垂指针 */
static void safe_free_fw(void) {
    free(g_fw_data);
    g_fw_data = NULL;
    g_fw_size = 0;
    free(g_fw_header);
    g_fw_header = NULL;
}

/* 加载固件（模拟从Flash读取） */
static int load_firmware(const uint8_t *src, size_t len) {
    if (src == NULL || len < sizeof(fw_header_t)) {
        return -1;
    }
    
    /* 边界检查：len必须合理 */
    if (len > 65536) {
        return -1;
    }
    
    safe_free_fw();  /* 先清理旧数据 */
    
    g_fw_header = (fw_header_t *)malloc(sizeof(fw_header_t));
    g_fw_data = (uint8_t *)malloc(len);
    if (g_fw_header == NULL || g_fw_data == NULL) {
        safe_free_fw();
        return -1;
    }
    
    memcpy(g_fw_header, src, sizeof(fw_header_t));
    memcpy(g_fw_data, src + sizeof(fw_header_t), len - sizeof(fw_header_t));
    g_fw_size = len - sizeof(fw_header_t);
    
    /* 校验magic和CRC */
    if (g_fw_header->magic != 0xAA || g_fw_header->crc != 0x12345678) {
        safe_free_fw();
        return -1;
    }
    
    return 0;
}

/* 获取固件版本（无锁访问，模拟中断上下文） */
uint16_t get_fw_version(void) {
    if (g_fw_header == NULL) {
        return 0;
    }
    return g_fw_header->fw_version;
}

/* 主流程：模拟固件升级 */
int main(void) {
    uint8_t fake_fw[64];
    memset(fake_fw, 0, sizeof(fake_fw));
    fake_fw[0] = 0xAA;
    fake_fw[4] = 0x78;  /* CRC低字节 */
    
    if (load_firmware(fake_fw, sizeof(fake_fw)) == 0) {
        printf("Firmware loaded, version: %u\n", get_fw_version());
    } else {
        printf("Load failed\n");
    }
    
    safe_free_fw();
    return 0;
}

