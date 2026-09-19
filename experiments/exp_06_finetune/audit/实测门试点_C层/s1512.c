#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define MAX_PASS_LEN 64
#define SALT_SIZE 16

int authenticate_user(const char *username, const char *password) {
    char stored_hash[EVP_MAX_MD_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    int result;

    // 模拟从数据库读取用户盐值和哈希
    FILE *db = fopen("user_db.txt", "r");
    if (!db) {
        return 0;
    }
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), db)) {
        if (strncmp(line, username, strlen(username)) == 0) {
            // 格式: username:salt:hash
            char *salt_hex = strtok(line + strlen(username) + 1, ":");
            char *hash_hex = strtok(NULL, "\n");
            // 将十六进制转换为字节
            for (int i = 0; i < SALT_SIZE; i++) {
                sscanf(salt_hex + 2*i, "%2hhx", &salt[i]);
            }
            for (int i = 0; i < EVP_MAX_MD_SIZE; i++) {
                sscanf(hash_hex + 2*i, "%2hhx", &stored_hash[i]);
            }
            found = 1;
            break;
        }
    }
    fclose(db);
    if (!found) {
        return 0;
    }

    // 使用固定IV进行PBKDF2派生
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                      10000, EVP_sha256(), EVP_MAX_MD_SIZE, hash);

    // 比较哈希
    result = CRYPTO_memcmp(hash, stored_hash, EVP_MAX_MD_SIZE);
    return (result == 0);
}

int main() {
    char username[64];
    char password[MAX_PASS_LEN];
    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    if (authenticate_user(username, password)) {
        printf("Access granted\n");
    } else {
        printf("Access denied\n");
    }
    return 0;
}

