#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    int id;
} User;

User *create_user(const char *name, int id) {
    User *u = (User *)malloc(sizeof(User));
    if (!u) return NULL;
    u->name = (char *)malloc(strlen(name) + 1);
    if (!u->name) {
        free(u);
        return NULL;
    }
    strcpy(u->name, name);
    u->id = id;
    return u;
}

void free_user(User *u) {
    if (!u) return;
    free(u->name);
    free(u);
}

void process_user(User *u) {
    if (!u || !u->name) return;
    printf("Processing user: %s (id=%d)\n", u->name, u->id);
    free_user(u);
    // 模拟后续业务逻辑
    printf("User name length: %zu\n", strlen(u->name));  // line 27: UAF
}

int main() {
    User *u = create_user("alice", 1001);
    if (!u) return 1;
    process_user(u);
    return 0;
}

