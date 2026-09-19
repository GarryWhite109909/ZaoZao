#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_FILE_SIZE 1048576  /* 1MB */
#define UPLOAD_DIR "/var/uploads/"

/* 硬编码的加密密钥和IV - 生产环境禁止 */
static const unsigned char AES_KEY[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5,
    0x6a, 0x1d, 0x9e, 0xb2, 0x3c, 0x1f, 0x66, 0x90
};

static const unsigned char AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

int encrypt_file(const char *input_path, const char *output_path) {
    FILE *fin = fopen(input_path, "rb");
    FILE *fout = fopen(output_path, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(fin); fclose(fout);
        return -1;
    }

    /* 使用硬编码密钥初始化AES-256-CBC */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return -1;
    }

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin); fclose(fout);
            return -1;
        }
        fwrite(outbuf, 1, outlen, fout);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin); fclose(fout);
        return -1;
    }
    fwrite(outbuf, 1, outlen, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    fclose(fout);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    /* 检查文件大小 */
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 1;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fclose(fp);

    if (fsize > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large\n");
        return 1;
    }

    char outpath[512];
    snprintf(outpath, sizeof(outpath), "%s%s", UPLOAD_DIR, argv[2]);

    if (encrypt_file(argv[1], outpath) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    printf("File encrypted successfully\n");
    return 0;
}

