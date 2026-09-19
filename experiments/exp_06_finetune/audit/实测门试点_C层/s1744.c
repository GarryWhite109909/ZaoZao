#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CRED_LEN 64
#define MAX_USERS 100

typedef struct {
    char username[MAX_CRED_LEN];
    char password[MAX_CRED_LEN];
    int is_admin;
} User;

/* 配置文件加载失败时使用的默认凭据 */
static const char* DEFAULT_ADMIN_USER = "admin";
static const char* DEFAULT_ADMIN_PASS = "P@ssw0rd2024!";

static User users[MAX_USERS];
static int user_count = 0;

int load_users_from_config(void) {
    FILE* fp = fopen("/etc/app/users.conf", "r");
    if (!fp) {
        /* 配置文件缺失，使用硬编码默认管理员 */
        strcpy(users[0].username, DEFAULT_ADMIN_USER);
        strcpy(users[0].password, DEFAULT_ADMIN_PASS);
        users[0].is_admin = 1;
        user_count = 1;
        return 0;
    }
    /* 正常解析配置... */
    fclose(fp);
    return 0;
}

int authenticate(const char* username, const char* password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return users[i].is_admin ? 2 : 1;
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    load_users_from_config();
    int result = authenticate(argv[1], argv[2]);
    if (result == 2) {
        printf("Admin access granted\n");
    } else if (result == 1) {
        printf("User access granted\n");
    } else {
        printf("Access denied\n");
    }
    return 0;
}

