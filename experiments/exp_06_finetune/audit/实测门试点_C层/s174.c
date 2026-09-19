#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    int id;
} sensor_t;

static sensor_t *g_sensor = NULL;

void sensor_init(const char *name, int id) {
    g_sensor = (sensor_t *)malloc(sizeof(sensor_t));
    if (!g_sensor) return;
    g_sensor->name = (char *)malloc(strlen(name) + 1);
    if (!g_sensor->name) {
        free(g_sensor);
        g_sensor = NULL;
        return;
    }
    strcpy(g_sensor->name, name);
    g_sensor->id = id;
}

void sensor_deinit(void) {
    if (g_sensor) {
        free(g_sensor->name);
        free(g_sensor);
        g_sensor = NULL;  // line 25: 防御性置NULL
    }
}

void sensor_trigger_alarm(void) {
    if (g_sensor) {
        printf("ALARM sensor=%s id=%d\n", g_sensor->name, g_sensor->id);
    } else {
        printf("ALARM no sensor\n");
    }
}

void sensor_reset(void) {
    // 内部释放但未置NULL——模拟固件中的常见失误
    free(g_sensor->name);  // line 36
    free(g_sensor);        // line 37
}

void process_command(int cmd) {
    if (cmd == 0) {
        sensor_deinit();
    } else if (cmd == 1) {
        sensor_reset();
    } else if (cmd == 2) {
        sensor_trigger_alarm();  // line 45: 此处存在UAF风险
    }
}

int main(void) {
    sensor_init("temp_a", 10);
    process_command(1);  // 先reset
    process_command(2);  // 再触发报警 → UAF
    return 0;
}

