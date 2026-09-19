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

void delete_user(User *u) {
    if (!u) return;
    free(u->name);
    free(u);
}

void process_user(User *u) {
    if (!u || !u->name) return;
    printf("Processing %s (id=%d)\n", u->name, u->id);
}

int main(int argc, char *argv[]) {
    User *user = create_user("alice", 42);
    if (!user) return 1;

    delete_user(user);
    // 模拟后续逻辑分支：某些路径下继续使用已释放指针
    if (argc > 2) {
        process_user(user);  // 潜在 UAF
    } else {
        printf("Skipped\n");
    }
    return 0;
}

