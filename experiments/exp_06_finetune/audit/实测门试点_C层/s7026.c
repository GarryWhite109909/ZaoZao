#include <stdio.h>
#include <string.h>

typedef struct {
    char username[32];
    char password[64];
} Account;

void init_account(Account* a) {
    strcpy(a->username, "admin");
    strcpy(a->password, "hardcoded_pw_123");
}

int main() {
    Account a;
    init_account(&a);
    printf("user=%s\n", a.username);
    return 0;
}

