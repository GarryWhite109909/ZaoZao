#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 10

typedef struct {
    char *name;
    int quantity;
} Item;

int main() {
    Item *inventory = (Item*)malloc(sizeof(Item) * MAX_ITEMS);
    if (!inventory) {
        return 1;
    }

    // Initialize inventory
    for (int i = 0; i < MAX_ITEMS; i++) {
        inventory[i].name = (char*)malloc(32);
        if (!inventory[i].name) {
            // Cleanup partial allocations
            for (int j = 0; j < i; j++) {
                free(inventory[j].name);
            }
            free(inventory);
            return 1;
        }
        snprintf(inventory[i].name, 32, "Item_%d", i);
        inventory[i].quantity = i;
    }

    // Process user input
    int idx;
    printf("Enter item index (0-%d): ", MAX_ITEMS - 1);
    scanf("%d", &idx);

    // Vulnerable: no bounds check on idx
    printf("Item: %s, Quantity: %d\n", inventory[idx].name, inventory[idx].quantity);

    // Cleanup
    for (int i = 0; i < MAX_ITEMS; i++) {
        free(inventory[i].name);
    }
    free(inventory);
    return 0;
}

