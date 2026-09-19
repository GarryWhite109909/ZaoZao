#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Embedded firmware: manages a fixed-size sensor configuration block */
#define CONFIG_MAGIC 0xA5A5A5A5
#define CONFIG_SIZE 64

typedef struct {
    uint8_t data[CONFIG_SIZE];
    uint32_t magic;
    uint8_t in_use;
} sensor_config_t;

static sensor_config_t *g_config = NULL;

/* Load config from flash (simulated) */
static sensor_config_t* load_config(void) {
    sensor_config_t *cfg = (sensor_config_t*)malloc(sizeof(sensor_config_t));
    if (!cfg) return NULL;
    
    memset(cfg, 0, sizeof(sensor_config_t));
    cfg->magic = CONFIG_MAGIC;
    cfg->in_use = 1;
    /* Simulate reading from flash... */
    return cfg;
}

/* Safely release config - NULLs pointer after free */
static void release_config(sensor_config_t **cfg_ptr) {
    if (cfg_ptr && *cfg_ptr) {
        free(*cfg_ptr);
        *cfg_ptr = NULL;  /* line 28: prevent dangling pointer */
    }
}

/* Apply calibration offset - reads config without ownership transfer */
static int apply_calibration(const sensor_config_t *cfg, int32_t offset) {
    if (!cfg || cfg->magic != CONFIG_MAGIC || !cfg->in_use) {
        return -1;  /* line 35: validate before any access */
    }
    /* Firmware-specific: bounded offset check */
    if (offset < -100 || offset > 100) {
        return -2;
    }
    int32_t raw = (int32_t)cfg->data[0] + offset;
    return (int)raw;
}

int main(void) {
    g_config = load_config();
    if (!g_config) {
        return -1;
    }

    /* Use config */
    int result = apply_calibration(g_config, 42);
    printf("Calibration result: %d\n", result);

    /* Proper cleanup - single owner, explicit NULL */
    release_config(&g_config);  /* line 55: g_config becomes NULL */

    /* Attempt to use after release - should be prevented */
    if (g_config != NULL) {  /* line 58: NULL check catches UAF */
        (void)apply_calibration(g_config, 10);
    } else {
        printf("Config already released, safe.\n");
    }

    return 0;
}

