#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 128

typedef struct {
    char name[64];
    int score;
} Player;

// 模拟从外部输入获取名字（不安全来源）
static void get_player_name(char *out, size_t size) {
    // 实际场景中此处会从socket/文件读取
    strcpy(out, "A_very_long_player_name_that_exceeds_the_expected_buffer_size_12345678901234567890");
}

int main(void) {
    Player *p = (Player *)malloc(sizeof(Player));
    if (!p) {
        return -1;
    }

    char temp[MAX_BUF];
    get_player_name(temp, sizeof(temp));

    // 第22行：将temp复制到p->name，但temp可能超过63字节
    strcpy(p->name, temp);

    printf("Player: %s, Score: %d\n", p->name, p->score);

    free(p);
    return 0;
}

