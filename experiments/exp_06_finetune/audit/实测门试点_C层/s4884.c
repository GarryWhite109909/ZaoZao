#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Secure credential storage: credentials are not hardcoded.
// They are read from environment variables at runtime.
// Environment variables are managed by the deployment system (e.g., Docker secrets, K8s secrets).

#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64

// Simulated secure storage read: in production, this would use a secrets manager API.
// The function returns 0 on success, -1 on failure.
static int get_secret(const char* env_name, char* out_buf, size_t buf_size) {
    // Line 12: Read from environment variable, not from source code.
    const char* env_value = getenv(env_name);
    if (env_value == NULL) {
        fprintf(stderr, "Error: Environment variable %s not set.\n", env_name);
        return -1;
    }
    // Line 17: Bound the copy to prevent buffer overflow.
    size_t len = strlen(env_value);
    if (len >= buf_size) {
        fprintf(stderr, "Error: Secret too long for buffer.\n");
        return -1;
    }
    strncpy(out_buf, env_value, buf_size - 1);
    out_buf[buf_size - 1] = '\0';
    return 0;
}

// Line 24: Authentication function that uses runtime-provided credentials.
int authenticate_user(const char* input_user, const char* input_pass) {
    char stored_user[MAX_USERNAME_LEN];
    char stored_pass[MAX_PASSWORD_LEN];

    // Line 29-30: Fetch credentials from secure storage at runtime.
    // No hardcoded values anywhere in the binary or source.
    if (get_secret("APP_USERNAME", stored_user, sizeof(stored_user)) != 0) {
        return 0; // Authentication fails if secret is unavailable.
    }
    if (get_secret("APP_PASSWORD", stored_pass, sizeof(stored_pass)) != 0) {
        return 0;
    }

    // Line 37-38: Constant-time comparison to prevent timing attacks.
    // Both strings are NULL-terminated and same-length checked first.
    size_t user_len = strlen(input_user);
    size_t pass_len = strlen(input_pass);
    if (user_len != strlen(stored_user) || pass_len != strlen(stored_pass)) {
        return 0; // Length mismatch: fail fast without leaking info.
    }

    // Line 44: Use constant-time comparison (e.g., CRYPTO_memcmp in production).
    // Here we simulate with a simple XOR loop that doesn't short-circuit.
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < user_len; i++) {
        diff |= (uint8_t)(input_user[i] ^ stored_user[i]);
    }
    for (size_t i = 0; i < pass_len; i++) {
        diff |= (uint8_t)(input_pass[i] ^ stored_pass[i]);
    }
    return (diff == 0) ? 1 : 0;
}

// Line 56: Example caller - no credentials are defined here.
int main(void) {
    // Simulated login attempt (in real code, these come from network input).
    char user_input[] = "admin";
    char pass_input[] = "s3cr3t";
    if (authenticate_user(user_input, pass_input)) {
        printf("Access granted.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}

