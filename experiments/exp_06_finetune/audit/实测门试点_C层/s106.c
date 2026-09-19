#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CHANNELS 8
#define SAMPLE_RATE 44100

typedef struct {
    int channel_count;
    int sample_count;
    short *audio_data;
} AudioBuffer;

int parse_audio_header(const unsigned char *header, int header_len, AudioBuffer *buf) {
    if (header_len < 8) {
        return -1;
    }
    buf->channel_count = header[0] & 0x0F;
    buf->sample_count = (header[4] << 8) | header[5];
    if (buf->channel_count > MAX_CHANNELS) {
        return -1;
    }
    return 0;
}

int load_audio_samples(AudioBuffer *buf, const unsigned char *stream, int stream_len) {
    int total_samples = buf->channel_count * buf->sample_count;
    if (total_samples > 4096) {
        return -1;
    }
    buf->audio_data = (short *)malloc(total_samples * sizeof(short));
    if (!buf->audio_data) {
        return -1;
    }
    for (int i = 0; i < total_samples; i++) {
        if ((i + 1) * 2 > stream_len) {
            free(buf->audio_data);
            return -1;
        }
        buf->audio_data[i] = (stream[2*i] << 8) | stream[2*i + 1];
    }
    return 0;
}

int process_audio_frame(AudioBuffer *buf, int frame_index) {
    int sample_offset = frame_index * buf->channel_count;
    short *frame = &buf->audio_data[sample_offset];
    for (int ch = 0; ch < buf->channel_count; ch++) {
        frame[ch] = (short)(frame[ch] * 1.5);
    }
    return 0;
}

int main(int argc, char **argv) {
    unsigned char header[16] = {0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
    unsigned char stream[1024] = {0};
    AudioBuffer buf;

    if (parse_audio_header(header, sizeof(header), &buf) != 0) {
        return -1;
    }
    if (load_audio_samples(&buf, stream, sizeof(stream)) != 0) {
        return -1;
    }
    process_audio_frame(&buf, 5);
    free(buf.audio_data);
    return 0;
}

