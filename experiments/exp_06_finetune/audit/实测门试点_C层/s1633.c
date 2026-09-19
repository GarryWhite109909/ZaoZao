#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONFIG_DIR "/etc/myapp/configs/"
#define MAX_PATH 256

/* Load configuration file by name, returns 0 on success */
int load_config(const char *config_name) {
    char path[MAX_PATH];
    FILE *fp;
    char line[512];
    char key[128], value[384];

    if (config_name == NULL || config_name[0] == '\0') {
        fprintf(stderr, "Invalid config name\n");
        return -1;
    }

    /* Build the full path to the config file */
    snprintf(path, sizeof(path), "%s%s", CONFIG_DIR, config_name);

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open config file: %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        /* Parse key=value pairs */
        if (sscanf(line, "%127[^=]=%383[^\n]", key, value) == 2) {
            printf("Setting: %s = %s\n", key, value);
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_name>\n", argv[0]);
        return 1;
    }
    return load_config(argv[1]);
}

