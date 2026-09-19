#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_LEN 32
#define IV_LEN 16

static const unsigned char fixed_key[KEY_LEN] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x76, 0x2e, 0x71, 0x60, 0x30, 0x1f, 0x0a, 0x9b,
    0xb1, 0x0d, 0x1a, 0x8c, 0x5e, 0x2f, 0x3d, 0x4a
};

static const unsigned char fixed_iv[IV_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, fixed_key, fixed_iv) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto cleanup;
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto cleanup;
    *ciphertext_len += len;

    ret = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main() {
    unsigned char plaintext[] = "Sensitive configuration data";
    unsigned char ciphertext[128];
    int ciphertext_len = 0;

    if (encrypt_data(plaintext, strlen((char*)plaintext), ciphertext, &ciphertext_len)) {
        printf("Encrypted %d bytes\n", ciphertext_len);
    }
    return 0;
}

