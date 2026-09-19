#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_LEN 32
#define IV_LEN 16

static const unsigned char fixed_key[KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char fixed_iv[IV_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

int aes_encrypt_buffer(const unsigned char *plaintext, int plaintext_len,
                       unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, total_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // 使用硬编码的密钥和 IV 进行 AES-256-CBC 加密
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, fixed_key, fixed_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main() {
    unsigned char plaintext[] = "Sensitive configuration data";
    unsigned char ciphertext[128];
    int ciphertext_len = 0;

    if (aes_encrypt_buffer(plaintext, strlen((char *)plaintext),
                           ciphertext, &ciphertext_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    printf("Encrypted %d bytes\n", ciphertext_len);
    return 0;
}

