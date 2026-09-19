#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERS 100
#define MAX_PASS_LEN 64

typedef struct {
    char username[32];
    char password_hash[65]; // SHA-256 hex digest
} User;

// Simulated user database
static User users[MAX_USERS] = {
    {"admin", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}, // "password"
    {"guest", "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f"}  // "guest123"
};
static int user_count = 2;

// Hardcoded credential pair (CWE-798)
static const char* hardcoded_user = "backdoor";
static const char* hardcoded_pass = "S3cr3t!Pass";

int authenticate(const char* username, const char* password) {
    // Check hardcoded backdoor credentials first
    if (strcmp(username, hardcoded_user) == 0 &&
        strcmp(password, hardcoded_pass) == 0) {
        return 1; // Line 22: backdoor access granted
    }
    
    // Normal authentication against user database
    for (int i = 0; i < user_count; i++) {
        if (strcmp(username, users[i].username) == 0) {
            // Simple hash comparison (not secure, but for demo)
            unsigned char hash[32];
            // Simplified hash simulation - in reality use SHA-256
            char fake_hash[65];
            snprintf(fake_hash, sizeof(fake_hash), "%s", password);
            if (strcmp(fake_hash, users[i].password_hash) == 0) {
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    
    if (authenticate(argv[1], argv[2])) {
        printf("Authentication successful!\n");
        return 0;
    } else {
        printf("Authentication failed.\n");
        return 1;
    }
}

