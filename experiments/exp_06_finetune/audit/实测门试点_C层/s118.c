#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    int id;
} User;

User* create_user(const char *name, int id) {
    User *u = (User*)malloc(sizeof(User));
    if (!u) return NULL;
    u->name = (char*)malloc(strlen(name) + 1);
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
    if (!u) return;
    printf("Processing user: %s (ID: %d)\n", u->name, u->id);
    /* Simulate some work */
    if (u->id > 100) {
        delete_user(u);
    }
    /* Bug: u is used after potential free */
    printf("Done processing %s\n", u->name);
}

int main() {
    User *admin = create_user("admin", 200);
    if (!admin) return 1;
    process_user(admin);
    return 0;
}

