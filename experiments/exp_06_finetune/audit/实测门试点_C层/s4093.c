#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 嵌入式固件：传感器数据采集模块 */
typedef struct {
    uint8_t *buffer;
    size_t length;
    int valid;
} sensor_data_t;

static sensor_data_t *g_sensor = NULL;

/* 初始化传感器数据缓冲区 */
static sensor_data_t *sensor_init(size_t size) {
    sensor_data_t *s = (sensor_data_t *)malloc(sizeof(sensor_data_t));
    if (!s) {
        return NULL;
    }
    s->buffer = (uint8_t *)malloc(size);
    if (!s->buffer) {
        free(s);
        return NULL;
    }
    s->length = size;
    s->valid = 1;
    return s;
}

/* 释放传感器数据（防御：释放后置NULL） */
static void sensor_free(sensor_data_t **s_ptr) {
    if (s_ptr && *s_ptr) {
        free((*s_ptr)->buffer);
        free(*s_ptr);
        *s_ptr = NULL;  /* line 31: 置NULL防止悬垂指针 */
    }
}

/* 处理传感器数据（防御：使用前检查） */
static int sensor_process(sensor_data_t *s) {
    if (!s || !s->buffer || !s->valid) {  /* line 36: 空指针与有效性检查 */
        return -1;
    }
    /* 模拟数据处理 */
    uint8_t sum = 0;
    for (size_t i = 0; i < s->length; i++) {
        sum += s->buffer[i];
    }
    return (int)sum;
}

int main(void) {
    g_sensor = sensor_init(64);
    if (!g_sensor) {
        return -1;
    }

    /* 正常处理 */
    int result = sensor_process(g_sensor);
    printf("Processed: %d\n", result);

    /* 释放并置NULL */
    sensor_free(&g_sensor);

    /* 释放后再次处理（安全：g_sensor已被置NULL） */
    int result2 = sensor_process(g_sensor);  /* line 57: 传入NULL，被line 36拦截 */
    if (result2 == -1) {
        printf("Sensor already freed, safe.\n");
    }

    /* 双重释放尝试（安全：二次调用sensor_free时*s_ptr为NULL） */
    sensor_free(&g_sensor);  /* line 62: 不会再次free */

    return 0;
}

