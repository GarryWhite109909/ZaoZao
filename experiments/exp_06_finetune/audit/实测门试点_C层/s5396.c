#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_LEN 32

typedef struct {
    char *name;
    int id;
} User;

User *create_user(const char *name, int id) {
    if (name == NULL) {
        return NULL;
    }
    
    size_t name_len = strlen(name);
    if (name_len >= MAX_NAME_LEN) {
        fprintf(stderr, "Name too long\n");
        return NULL;
    }
    
    User *user = (User *)malloc(sizeof(User));
    if (user == NULL) {
        return NULL;
    }
    
    user->name = (char *)malloc(name_len + 1);
    if (user->name == NULL) {
        free(user);
        return NULL;
    }
    
    strcpy(user->name, name);
    user->id = id;
    return user;
}

void destroy_user(User *user) {
    if (user == NULL) {
        return;
    }
    free(user->name);
    user->name = NULL;
    free(user);
}

int main() {
    const char *input = "Alice";
    User *u = create_user(input, 1);
    if (u == NULL) {
        return 1;
    }
    
    printf("User: %s (ID: %d)\n", u->name, u->id);
    destroy_user(u);
    
    return 0;
}

