#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    int length;
} Sensor;

Sensor *sensor_create(const char *name, int length) {
    if (name == NULL || length <= 0) {
        return NULL;
    }
    Sensor *s = (Sensor *)malloc(sizeof(Sensor));
    if (s == NULL) {
        return NULL;
    }
    s->name = (char *)malloc(length + 1);
    if (s->name == NULL) {
        free(s);
        return NULL;
    }
    strncpy(s->name, name, length);
    s->name[length] = '\0';
    s->length = length;
    return s;
}

void sensor_destroy(Sensor *s) {
    if (s == NULL) {
        return;
    }
    free(s->name);
    s->name = NULL;  // line 25: Prevent dangling pointer
    free(s);
}

void sensor_print(const Sensor *s) {
    if (s == NULL || s->name == NULL) {
        printf("Sensor: invalid\n");
        return;
    }
    printf("Sensor: %s (len=%d)\n", s->name, s->length);
}

int main(void) {
    Sensor *sensor = sensor_create("temp", 4);
    if (sensor == NULL) {
        return 1;
    }
    sensor_print(sensor);
    sensor_destroy(sensor);
    sensor = NULL;  // line 43: Prevent use-after-free
    sensor_print(sensor);  // safe: NULL check in sensor_print
    return 0;
}

