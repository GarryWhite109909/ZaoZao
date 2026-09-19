// audio_buf_safe.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char *alloc_audio_buf(size_t samples, size_t channels, size_t bytes_per_sample) {
    if (samples == 0 || channels == 0 || bytes_per_sample == 0) return NULL;
    if (channels > SIZE_MAX / bytes_per_sample) return NULL;
    size_t frame_size = channels * bytes_per_sample;
    if (samples > SIZE_MAX / frame_size) return NULL;
    size_t total = samples * frame_size;
    char *buf = malloc(total);
    if (buf) memset(buf, 0, total);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 4) return 1;
    char *buf = alloc_audio_buf(
        strtoul(argv[1], NULL, 10),
        strtoul(argv[2], NULL, 10),
        strtoul(argv[3], NULL, 10));
    if (buf) free(buf);
    return 0;
}

