#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[16];
    int enabled;
} Sensor;

Sensor* sensor_list[8];
int sensor_count = 0;

Sensor* create_sensor(const char* name, int enabled) {
    Sensor* s = (Sensor*)malloc(sizeof(Sensor));
    if (!s) return NULL;
    strncpy(s->name, name, sizeof(s->name) - 1);
    s->name[sizeof(s->name) - 1] = '\0';
    s->enabled = enabled;
    return s;
}

void remove_sensor(int idx) {
    if (idx < 0 || idx >= sensor_count) return;
    free(sensor_list[idx]);
    /* 注意：未将 sensor_list[idx] 置为 NULL */
}

int process_sensor(int idx) {
    if (idx < 0 || idx >= sensor_count) return -1;
    Sensor* s = sensor_list[idx];
    if (!s) return -1;
    return s->enabled ? s->name[0] : 0;
}

int main() {
    sensor_list[sensor_count++] = create_sensor("temp", 1);
    sensor_list[sensor_count++] = create_sensor("hum", 0);

    remove_sensor(0);
    /* 漏洞触发：remove 后未置 NULL，此处 use-after-free */
    int result = process_sensor(0);
    printf("Result: %d\n", result);

    free(sensor_list[1]);
    return 0;
}

