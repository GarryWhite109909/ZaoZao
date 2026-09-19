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

int main(void) {
    User *u = create_user("alice", 1);
    if (!u) return 1;

    delete_user(u);

    printf("User name: %s\n", u->name);  // 此处使用已释放的 u->name
    printf("User id: %d\n", u->id);      // 此处使用已释放的 u

    return 0;
}

