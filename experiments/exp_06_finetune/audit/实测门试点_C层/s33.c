#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME_LEN 32

typedef struct {
    char *name;
    int id;
} User;

User* create_user(const char *input) {
    User *u = (User*)malloc(sizeof(User));
    if (!u) return NULL;
    u->name = (char*)malloc(MAX_NAME_LEN);
    if (!u->name) {
        free(u);
        return NULL;
    }
    u->id = 0;
    /* line 17: 直接复制用户输入，未检查长度 */
    strcpy(u->name, input);
    return u;
}

void print_user(User *u) {
    if (u && u->name) {
        printf("User: %s (ID: %d)\n", u->name, u->id);
    }
}

void cleanup_user(User *u) {
    if (u) {
        free(u->name);
        free(u);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <name>\n", argv[0]);
        return 1;
    }
    User *u = create_user(argv[1]);
    if (!u) {
        printf("Failed to create user\n");
        return 1;
    }
    print_user(u);
    cleanup_user(u);
    return 0;
}

