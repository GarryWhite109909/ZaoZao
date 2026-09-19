#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SENSOR_READINGS 4

typedef struct {
    int sensor_id;
    float temperature;
} sensor_data_t;

static sensor_data_t *g_sensor_buffer = NULL;
static int g_buffer_size = 0;

/* Initialize sensor buffer with dynamic allocation */
int sensor_buffer_init(int num_sensors) {
    if (num_sensors <= 0 || num_sensors > MAX_SENSOR_READINGS) {
        return -1;
    }
    
    sensor_data_t *new_buffer = (sensor_data_t *)malloc(
        num_sensors * sizeof(sensor_data_t)
    );
    if (!new_buffer) {
        return -1;
    }
    
    /* Free old buffer if exists (defensive) */
    if (g_sensor_buffer) {
        free(g_sensor_buffer);
        g_sensor_buffer = NULL;  /* line 25: NULL after free */
    }
    
    g_sensor_buffer = new_buffer;
    g_buffer_size = num_sensors;
    memset(g_sensor_buffer, 0, num_sensors * sizeof(sensor_data_t));
    return 0;
}

/* Update sensor reading at given index */
int sensor_update(int index, float temperature) {
    if (!g_sensor_buffer || index < 0 || index >= g_buffer_size) {
        return -1;
    }
    
    g_sensor_buffer[index].sensor_id = index;
    g_sensor_buffer[index].temperature = temperature;
    return 0;
}

/* Cleanup and release all resources */
void sensor_buffer_deinit(void) {
    if (g_sensor_buffer) {
        free(g_sensor_buffer);
        g_sensor_buffer = NULL;  /* line 47: NULL after free */
    }
    g_buffer_size = 0;
}

int main(void) {
    /* Simulate firmware initialization */
    if (sensor_buffer_init(3) != 0) {
        return -1;
    }
    
    sensor_update(0, 25.5f);
    sensor_update(1, 26.1f);
    
    /* Re-initialize to simulate reconfiguration */
    if (sensor_buffer_init(2) != 0) {
        sensor_buffer_deinit();
        return -1;
    }
    
    /* Update after re-init */
    sensor_update(1, 27.3f);
    
    sensor_buffer_deinit();
    return 0;
}

