#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char *name;
} User;

void free_user(User *u) {
    if (u) {
        free(u->name);
        free(u);
    }
}

User *create_user(int id, const char *name) {
    User *u = (User *)malloc(sizeof(User));
    if (!u) return NULL;
    u->id = id;
    u->name = (char *)malloc(strlen(name) + 1);
    if (!u->name) {
        free(u);
        return NULL;
    }
    strcpy(u->name, name);
    return u;
}

void process_user(User *u, int action) {
    if (action == 0) {
        free_user(u);
    }
    // 模拟其他处理
    printf("Processing user %d: %s\n", u->id, u->name);
}

int main() {
    User *user = create_user(1, "alice");
    if (!user) return 1;
    process_user(user, 0);
    // 后续代码再次使用已释放的指针
    printf("Final: %s\n", user->name);
    free_user(user);
    return 0;
}

