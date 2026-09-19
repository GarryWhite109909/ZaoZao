#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>

#define MAX_PATH 256

/* Read configuration file based on user-supplied name */
int read_config(const char *user_input) {
    char filepath[MAX_PATH];
    char buffer[128];
    int fd;

    printf("Loading configuration: %s\n", user_input);

    /* Construct path to config directory */
    snprintf(filepath, sizeof(filepath), "/etc/myapp/configs/%s", user_input);

    /* Open and read the file */
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes < 0) {
        perror("read");
        close(fd);
        return -1;
    }
    buffer[bytes] = '\0';
    close(fd);

    printf("Config content: %s\n", buffer);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_name>\n", argv[0]);
        return 1;
    }

    return read_config(argv[1]);
}

