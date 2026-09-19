#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_BUF_SIZE 64
#define SENSOR_ID_LEN 8

typedef struct {
    char sensor_id[SENSOR_ID_LEN];
    uint16_t raw_value;
    char status[16];
} sensor_reading_t;

static int process_sensor_data(const uint8_t *input, size_t input_len, sensor_reading_t *out)
{
    if (input == NULL || out == NULL) {
        return -1;
    }

    /* 防御1: 输入长度硬性校验，防止缓冲区溢出 */
    if (input_len != SENSOR_ID_LEN + sizeof(uint16_t) + 15) {
        return -2;
    }

    /* 防御2: 逐字段拷贝并验证长度 */
    memcpy(out->sensor_id, input, SENSOR_ID_LEN);
    out->sensor_id[SENSOR_ID_LEN - 1] = '\0';  /* 确保字符串终止 */

    memcpy(&out->raw_value, input + SENSOR_ID_LEN, sizeof(uint16_t));
    out->raw_value = (uint16_t)(out->raw_value & 0x0FFF);  /* 12位ADC值掩码 */

    memcpy(out->status, input + SENSOR_ID_LEN + sizeof(uint16_t), 15);
    out->status[15] = '\0';  /* 状态字符串固定15字符+终止符 */

    /* 防御3: 状态字段内容白名单校验 */
    if (strcmp(out->status, "OK") != 0 && strcmp(out->status, "WARN") != 0) {
        return -3;
    }

    return 0;
}

int main(void)
{
    uint8_t packet[32] = {0};
    sensor_reading_t reading;
    int ret;

    /* 模拟从UART接收的固定格式数据包 */
    memcpy(packet, "SENSOR01", SENSOR_ID_LEN);
    packet[SENSOR_ID_LEN] = 0x34;
    packet[SENSOR_ID_LEN + 1] = 0x12;
    memcpy(packet + SENSOR_ID_LEN + 2, "OK", 2);

    ret = process_sensor_data(packet, sizeof(packet), &reading);
    if (ret == 0) {
        printf("Sensor ID: %s\n", reading.sensor_id);
        printf("Raw ADC: %u\n", reading.raw_value);
        printf("Status: %s\n", reading.status);
    }

    return 0;
}

