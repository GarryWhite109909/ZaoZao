#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 10

typedef struct {
    int id;
    char name[32];
} Item;

static Item* items[MAX_ITEMS];
static int item_count = 0;

static void cleanup_items(void) {
    for (int i = 0; i < item_count; i++) {
        if (items[i] != NULL) {
            free(items[i]);
            items[i] = NULL;
        }
    }
    item_count = 0;
}

int add_item(int id, const char* name) {
    if (item_count >= MAX_ITEMS) {
        return -1;
    }
    Item* new_item = (Item*)malloc(sizeof(Item));
    if (new_item == NULL) {
        return -1;
    }
    new_item->id = id;
    strncpy(new_item->name, name, sizeof(new_item->name) - 1);
    new_item->name[sizeof(new_item->name) - 1] = '\0';
    
    items[item_count] = new_item;
    item_count++;
    return 0;
}

void process_items(void) {
    for (int i = 0; i < item_count; i++) {
        printf("Processing item %d: %s\n", items[i]->id, items[i]->name);
    }
}

int main(void) {
    add_item(1, "First");
    add_item(2, "Second");
    
    process_items();
    cleanup_items();
    
    // 模拟重复清理场景（漏洞触发点）
    cleanup_items();
    
    return 0;
}

