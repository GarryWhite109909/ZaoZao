#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_FILE_SIZE 1024 * 1024
#define UPLOAD_DIR "/var/www/uploads/"

typedef struct {
    unsigned char key[32];
    unsigned char iv[16];
} CryptoContext;

int encrypt_file(const char *input_path, const char *output_path, CryptoContext *ctx) {
    FILE *in = fopen(input_path, "rb");
    if (!in) return -1;

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) {
        fclose(in);
        fclose(out);
        return -1;
    }

    if (EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(), NULL, ctx->key, ctx->iv) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        fclose(in);
        fclose(out);
        return -1;
    }

    unsigned char in_buf[4096];
    unsigned char out_buf[4096 + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;

    while ((in_len = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        if (EVP_EncryptUpdate(evp_ctx, out_buf, &out_len, in_buf, in_len) != 1) {
            EVP_CIPHER_CTX_free(evp_ctx);
            fclose(in);
            fclose(out);
            return -1;
        }
        fwrite(out_buf, 1, out_len, out);
    }

    if (EVP_EncryptFinal_ex(evp_ctx, out_buf, &out_len) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        fclose(in);
        fclose(out);
        return -1;
    }
    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(evp_ctx);
    fclose(in);
    fclose(out);
    return 0;
}

int handle_upload(const char *filename) {
    char in_path[256];
    char out_path[256];
    snprintf(in_path, sizeof(in_path), "/tmp/%s", filename);
    snprintf(out_path, sizeof(out_path), UPLOAD_DIR "%s.enc", filename);

    CryptoContext ctx;
    memcpy(ctx.key, "FixThisKey12345678FixThisKey123456", 32);
    memcpy(ctx.iv, "FixedIV_12345678", 16);

    return encrypt_file(in_path, out_path, &ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    return handle_upload(argv[1]);
}

